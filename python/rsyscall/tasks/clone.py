"""Make a new thread by calling clone

That is to say, make a new thread the normal way.

"""
from __future__ import annotations
from dataclasses import dataclass
from rsyscall._raw import ffi # type: ignore
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.handle import Stack, WrittenPointer, Pointer, FutexNode, FileDescriptor, Task, FutexNode
from rsyscall.loader import Trampoline, NativeLoader
from rsyscall.memory.allocator import Arena
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.struct import Int32
from rsyscall.tasks.base_sysif import BaseSyscallInterface
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.near.sysif import SyscallHangup
import contextlib
import logging
import rsyscall.far as far
import rsyscall.handle as handle
import trio
import typing as t

from rsyscall.sched import CLONE
from rsyscall.signal import SIG
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.wait import W

__all__ = [
    'ChildExit',
    'MMRelease',
    'ChildSyscallInterface',
    'launch_futex_monitor',
    'clone_child_task',
    'CloneThread',
]

class ChildExit(SyscallHangup):
    "The task we were sending syscalls to has exited"
    pass

class MMRelease(SyscallHangup):
    """The task we were sending syscalls to has either exited or exec'd; either way it can no longer respond

    More concretely, the task has left its old address space - it has called the
    mm_release kernel function (hence the name of this class).

    """
    pass


class ChildSyscallInterface(BaseSyscallInterface):
    """A connection to an rsyscall server that is one of our child processes

    We take as arguments here not only a SyscallConnection, but also an
    AsyncChildProcess monitoring the child process to which we will send
    syscalls.

    This is useful for situations where we can't rely on getting an EOF if the
    other side of a connection dies. That will happen, for example, whenever the
    child process is sharing a file descriptor table with us. In those
    situations, we need some other means to detect that a syscall will never be
    responded to, and signal it to the caller by throwing SyscallHangup.

    In this class, we detect a hangup while waiting for a syscall response by
    simultaneously monitoring the child process. If the child process exits, we
    stop waiting for the syscall response and throw SyscallHangup back to the
    caller.

    This is not just a matter of failure cases, it's also important for normal
    functionality. Detecting a hangup is our only way to discern whether a call
    to exit() was successful, and rsyscall.near.exit treats receiving an
    RsycallHangup as successful.

    We also take a futex_process: AsyncChildProcess. This is also used for
    normal functionality: futex_process should exit when the process has
    successfully called exec. This is again our only way of detecting a
    successful call to exec, and rsyscall.near.execve treats receiving an
    RsycallHangup as successful. (Concretely, futex_process will also exit when
    the process exits, not just when it execs, but that's harmless)

    A better way of detecting exec success would be great...

    """
    def __init__(self,
                 rsyscall_connection: SyscallConnection,
                 server_process: AsyncChildProcess,
                 futex_process: t.Optional[AsyncChildProcess],
    ) -> None:
        super().__init__(rsyscall_connection)
        self.server_process = server_process
        self.futex_process = futex_process
        self.logger = logging.getLogger(f"rsyscall.ChildSyscallInterface.{int(self.server_process.process.near)}")

    @contextlib.asynccontextmanager
    async def _throw_on_child_exit(self) -> t.AsyncGenerator[None, None]:
        """Monitor the child process and throw if it exits or execs

        Naturally, if the child does exit or exec while we're in the context
        manager body, we'll cancel the context manager body so that we don't
        spend forever waiting on a dead child.

        This is useful for detecting a situation where we've sent a request and
        will never receive a response, particularly for syscalls as documented
        in the module docstring.

        The application to syscalls is the primary purpose of this method; but
        this method is also useful for some other thread implementations, so we
        expose it with this relatively generic interface.

        """
        child_exited = False
        futex_exited = False
        got_result = False
        async with trio.open_nursery() as nursery:
            async def server_exit() -> None:
                await self.server_process.waitpid(W.EXITED)
                nonlocal child_exited
                child_exited = True
                nursery.cancel_scope.cancel()
            async def futex_exit() -> None:
                if self.futex_process is not None:
                    await self.futex_process.waitpid(W.EXITED)
                    nonlocal futex_exited
                    futex_exited = True
                    nursery.cancel_scope.cancel()
            nursery.start_soon(server_exit)
            nursery.start_soon(futex_exit)
            yield
            got_result = True
            nursery.cancel_scope.cancel()
        if got_result:
            return
        elif child_exited:
            # this takes precedence over MMRelease, since it gives us more information
            raise ChildExit()
        elif futex_exited:
            raise MMRelease()

    @contextlib.asynccontextmanager
    async def _throw_on_conn_error(self) -> t.AsyncGenerator[None, None]:
        async with self._throw_on_child_exit():
            yield

async def launch_futex_monitor(ram: RAM,
                               loader: NativeLoader, monitor: ChildProcessMonitor,
                               futex_pointer: WrittenPointer[FutexNode]) -> AsyncChildProcess:
    """Launch a process to wait on a futex; then we monitor the process to monitor the futex

    This process calls futex(futex_pointer, FUTEX_WAIT, futex_pointer.value) and
    then exits, so this process will exit if and when the futex has FUTEX_WAKE
    called on it.

    Sadly, this is the best we can do with integrating futexes into our event
    loop. There used to be a way to get a file descriptor to represent a futex,
    but it was removed because it was racy.

    Something better would be really great - especially because it would allow
    incorporating pthreads locks and other shared memory concurrency mechanisms
    based on futexes, into a normal event loop.

    """
    async def op(sem: RAM) -> t.Tuple[Pointer[Stack], WrittenPointer[Stack]]:
        stack_value = loader.make_trampoline_stack(Trampoline(
            loader.futex_helper_func, [
                int(futex_pointer.near + ffi.offsetof('struct futex_node', 'futex')),
                futex_pointer.value.futex]))
        stack_buf = await sem.malloc(Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        return stack
    stack = await ram.perform_batch(op)
    futex_process = await monitor.clone(CLONE.VM|CLONE.FILES, stack)
    # wait for futex helper to SIGSTOP itself,
    # which indicates the trampoline is done and we can deallocate the stack.
    state = await futex_process.waitpid(W.EXITED|W.STOPPED)
    if state.state(W.EXITED):
        raise Exception("thread internal futex-waiting task died unexpectedly", state)
    # resume the futex_process so it can start waiting on the futex
    await futex_process.kill(SIG.CONT)
    # TODO uh we need to actually call something to free the stack
    return futex_process

async def clone_child_task(
        parent: CloneThread,
        flags: CLONE,
        trampoline_func: t.Callable[[FileDescriptor], Trampoline],
) -> t.Tuple[AsyncChildProcess, Task]:
    """Clone a new child process and setup the sysif and task to manage it

    We rely on trampoline_func to take a socket and give us a native function call with
    arguments that will speak the rsyscall protocol over that socket.

    We also create a futex process, which we use to monitor the ctid futex.
    This process allows us to detect when the child successfully finishes an
    exec; see the docstring of ChildSyscallInterface.  Because we set
    CLONE.CHILD_CLEARTID, the ctid futex will receive a FUTEX_WAKE when the
    child process exits or execs, and the futex process will accordingly exit.

    """
    # This flag is mandatory; if we don't use CLONE_VM then CHILD_CLEARTID doesn't work
    # properly and we need to do more arcane things; see tasks.exec.
    flags |= CLONE.VM
    # Open a channel which we'll use for the rsyscall connection
    [(access_sock, remote_sock)] = await parent.connection.open_async_channels(1)
    # Create a trampoline that will start the new process running an rsyscall server
    trampoline = trampoline_func(remote_sock)
    # TODO it is unclear why we sometimes need to make a new mapping here, instead of
    # allocating with our normal allocator; all our memory is already MAP.SHARED, I think.
    # We should resolve this so we can use the normal allocator.
    arena = Arena(await parent.task.mmap(4096*2, PROT.READ|PROT.WRITE, MAP.SHARED))
    async def op(sem: RAM) -> t.Tuple[t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                                                       WrittenPointer[FutexNode]]:
        stack_value = parent.loader.make_trampoline_stack(trampoline)
        stack_buf = await sem.malloc(Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        futex_pointer = await sem.ptr(FutexNode(None, Int32(1)))
        return stack, futex_pointer
    # Create the stack we'll need, and the zero-initialized futex
    stack, futex_pointer = await parent.ram.perform_batch(op, arena)
    # it's important to start the processes in this order, so that the thread
    # process is the first process started; this is relevant in several
    # situations, including unshare(NEWPID) and manipulation of ns_last_pid
    child_process = await parent.monitor.clone(flags|CLONE.CHILD_CLEARTID, stack, ctid=futex_pointer)
    futex_process = await launch_futex_monitor(
        parent.ram, parent.loader, parent.monitor, futex_pointer)
    # Create the new syscall interface, which needs to use not just the connection,
    # but also the child process and the futex process.
    syscall = ChildSyscallInterface(SyscallConnection(access_sock, access_sock),
                                    child_process, futex_process)
    # Set up the new task with appropriately inherited namespaces, tables, etc.
    # TODO correctly track all the namespaces we're in
    if flags & CLONE.NEWPID:
        pidns = far.PidNamespace(child_process.process.near.id)
    else:
        pidns = parent.task.pidns
    if flags & CLONE.FILES:
        fd_table = parent.task.fd_table
    else:
        fd_table = handle.FDTable(child_process.process.near.id, parent.task.fd_table)
    task = Task(syscall, child_process.process,
                fd_table, parent.task.address_space, pidns)
    task.sigmask = parent.task.sigmask
    # Move ownership of the remote sock into the task and store it so it isn't closed
    remote_sock_handle = remote_sock.inherit(task)
    await remote_sock.invalidate()
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    return child_process, task

from rsyscall.epoller import Epoller
from rsyscall.network.connection import Connection, ConnectionThread
class CloneThread(ConnectionThread):
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 epoller: Epoller,
                 connection: Connection,
                 loader: NativeLoader,
                 monitor: ChildProcessMonitor,
    ) -> None:
        super().__init__(task, ram, epoller, connection)
        self.loader = loader
        self.monitor = monitor

    def _init_from(self, thr: CloneThread) -> None: # type: ignore
        super()._init_from(thr)
        self.loader = thr.loader
        self.monitor = thr.monitor

    async def _clone_task(self, flags: CLONE) -> t.Tuple[AsyncChildProcess, Task]:
        return await clone_child_task(
            self, flags, lambda sock: Trampoline(self.loader.server_func, [sock, sock]))

