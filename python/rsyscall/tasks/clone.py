"""Make a new process by calling clone

That is to say, make a new process the normal way.

"""
from __future__ import annotations
from dneio import reset
from dataclasses import dataclass
from rsyscall._raw import ffi # type: ignore
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.handle import Stack, WrittenPointer, Pointer, FutexNode, FileDescriptor, Task, FutexNode
from rsyscall.loader import Trampoline, NativeLoader
from rsyscall.memory.allocator import Arena
from rsyscall.monitor import AsyncChildPid, ChildPidMonitor
from rsyscall.network.connection import Connection
from rsyscall.struct import Int32
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.near.sysif import SyscallError
import contextlib
import logging
import rsyscall.far as far
import rsyscall.handle as handle
import trio
import typing as t

from rsyscall.sched import CLONE
from rsyscall.signal import SIG
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.socket import SHUT
from rsyscall.sys.wait import W

__all__ = [
    'launch_futex_monitor',
    'clone_child_task',
]

logger = logging.getLogger(__name__)

async def launch_futex_monitor(
                               loader: NativeLoader, monitor: ChildPidMonitor,
                               futex_pointer: WrittenPointer[FutexNode]) -> AsyncChildPid:
    """Launch a process to wait on a futex; then we monitor the process to monitor the futex

    This process calls futex(futex_pointer, FUTEX_WAIT, futex_pointer.value) and
    then exits, so this process will exit if and when the futex has FUTEX_WAKE
    called on it.

    Sadly, this is the best we can do with integrating futexes into our event
    loop. There used to be a way to get a file descriptor to represent a futex,
    but it was removed because it was racy.

    Something better would be really great - especially because it would allow
    incorporating pprocesss locks and other shared memory concurrency mechanisms
    based on futexes, into a normal event loop.

    """
    stack_value = loader.make_trampoline_stack(Trampoline(
        loader.futex_helper_func, [
            int(futex_pointer.near + ffi.offsetof('struct futex_node', 'futex')),
            futex_pointer.value.futex]))
    stack_buf = await monitor.cloning_task.malloc(Stack, 4096)
    stack = await stack_buf.write_to_end(stack_value, alignment=16)
    futex_pid = await monitor.clone(CLONE.VM|CLONE.FILES, stack)
    # wait for futex helper to SIGSTOP itself,
    # which indicates the trampoline is done and we can deallocate the stack.
    state = await futex_pid.waitpid(W.EXITED|W.STOPPED)
    if state.state(W.EXITED):
        raise Exception("process internal futex-waiting task died unexpectedly", state)
    # resume the futex_process so it can start waiting on the futex
    await futex_pid.kill(SIG.CONT)
    # TODO uh we need to actually call something to free the stack
    return futex_pid

async def clone_child_task(
        task: Task,
        connection: Connection,
        loader: NativeLoader,
        monitor: ChildPidMonitor,
        flags: CLONE,
        trampoline_func: t.Callable[[FileDescriptor], Trampoline],
) -> t.Tuple[AsyncChildPid, Task]:
    """Clone a new child process and setup the sysif and task to manage it

    We rely on trampoline_func to take a socket and give us a native function call with
    arguments that will speak the rsyscall protocol over that socket.

    We want to see EOF on our local socket if that remote socket is no longer being read;
    for example, if the process exits or execs.
    This is not automatic for us: Since the process might share its file descriptor table
    with other processes, remote_sock might not be closed when the process exits or execs.

    To ensure that we get an EOF, we use the ctid futex, which, thanks to
    CLONE.CHILD_CLEARTID, will be cleared and receive a futex wakeup when the child
    process exits or execs.

    When we see that futex wakeup (from Python, with the futex integrated into our event
    loop through launch_futex_monitor), we call shutdown(SHUT.RDWR) on the local socket
    from the parent. This results in future reads returning EOF.

    """
    # These flags are mandatory; if we don't use CLONE_VM then CHILD_CLEARTID doesn't work
    # properly and our only other recourse to detect exec is to abuse robust futexes.
    flags |= CLONE.VM|CLONE.CHILD_CLEARTID
    # Open a channel which we'll use for the rsyscall connection
    [(access_sock, remote_sock)] = await connection.open_async_channels(1)
    # Create a trampoline that will start the new process running an rsyscall server
    trampoline = trampoline_func(remote_sock)
    # TODO it is unclear why we sometimes need to make a new mapping here, instead of
    # allocating with our normal allocator; all our memory is already MAP.SHARED, I think.
    # We should resolve this so we can use the normal allocator.
    arena = Arena(await task.mmap(4096*2, PROT.READ|PROT.WRITE, MAP.SHARED))
    # Create the stack we'll need, and the zero-initialized futex
    stack_value = loader.make_trampoline_stack(trampoline)
    stack_buf = await task.malloc(Stack, 4096)
    stack = await stack_buf.write_to_end(stack_value, alignment=16)
    futex_pointer = await task.ptr(FutexNode(None, Int32(1)))
    # it's important to start the processes in this order, so that the process
    # process is the first process started; this is relevant in several
    # situations, including unshare(NEWPID) and manipulation of ns_last_pid
    child_pid = await monitor.clone(flags, stack, ctid=futex_pointer)
    # We want to be able to rely on getting an EOF if the other side of the syscall
    # connection is no longer being read (e.g., if the process exits or execs).  Since the
    # process might share its file descriptor table with other processes, remote_sock
    # might not be closed when the process exits or execs. To ensure that we get an EOF,
    # we use the ctid futex, which will be cleared on process exit or exec; we shutdown
    # access_sock when the ctid futex is cleared, to get an EOF.
    # We do this with launch_futex_monitor and a background coroutine.
    futex_pid = await launch_futex_monitor(loader, monitor, futex_pointer)
    async def shutdown_access_sock_on_futex_process_exit():
        try:
            await futex_pid.waitpid(W.EXITED)
        except SyscallError:
            # if the parent of the futex_process dies, this syscall
            # connection is broken anyway, so shut it down.
            pass
        await access_sock.handle.shutdown(SHUT.RDWR)
    # Running this in the background, without an associated object, is a bit dubious...
    reset(shutdown_access_sock_on_futex_process_exit())
    # Set up the new task with appropriately inherited namespaces, tables, etc.
    # TODO correctly track all the namespaces we're in
    if flags & CLONE.NEWPID:
        pidns = far.PidNamespace(child_pid.pid.near.id)
    else:
        pidns = task.pidns
    if flags & CLONE.FILES:
        fd_table = task.fd_table
    else:
        fd_table = handle.FDTable(child_pid.pid.near.id, task.fd_table)
    child_task = Task(
        child_pid.pid, fd_table, task.address_space, pidns)
    child_task.sigmask = task.sigmask
    # Move ownership of the remote sock into the task and store it so it isn't closed
    remote_sock_handle = remote_sock.inherit(child_task)
    await remote_sock.invalidate()
    # Create the new syscall interface, which needs to use not just the connection,
    # but also the futex process.
    child_task.sysif = SyscallConnection(
        logger.getChild(str(child_pid.pid.near)),
        access_sock,
        remote_sock_handle,
    )
    child_task.allocator = task.allocator.inherit(child_task)
    return child_pid, child_task
