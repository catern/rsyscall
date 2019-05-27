"""Functions for creating a thread from the standalone "rsyscall-server" executable

Note that these functions are not very useful; to exec rsyscall-server, we already need to
have a working ChildThread, so we don't get any more capabilities. We do unshare our
address space and perform all the other transitions of exec, but that's of limited
utility. At the moment, the primary use of these functions is for stress testing the rest
of rsyscall: Does everything keep working after we've unshared our address space?

"""
from __future__ import annotations
from dataclasses import dataclass
from rsyscall.command import Command
from rsyscall.epoller import AsyncReadBuffer
from rsyscall.handle import WrittenPointer, Pointer, MemoryTransport, Task, FileDescriptor, MemoryMapping
from rsyscall.thread import ChildThread, Thread
from rsyscall.loader import NativeLoader
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.monitor import AsyncChildProcess
from rsyscall.tasks.fork import launch_futex_monitor, ChildSyscallInterface
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.memory.ram import RAM
import rsyscall.far as far
import rsyscall.memory.allocator as memory
import rsyscall.near as near
import rsyscall.nix as nix
import typing as t

from rsyscall.fcntl import F
from rsyscall.struct import Int32
from rsyscall.linux.futex import FutexNode, RobustListHead, FUTEX_WAITERS, FUTEX_TID_MASK
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.memfd import MFD
from rsyscall.path import Path

__all__ = [
    "RsyscallServerExecutable",
    "spawn_exec",
    "rsyscall_exec",
]

async def set_singleton_robust_futex(
        task: Task, ram: RAM, allocator: memory.AllocatorInterface,
) -> WrittenPointer[FutexNode]:
    "Set the robust list of `task` to a list containing exactly one futex, and return that futex"
    # have to set the futex pointer to this value or the kernel won't wake on it
    futex_value = FUTEX_WAITERS|(int(task.process.near) & FUTEX_TID_MASK)
    async def op(sem: RAM) -> t.Tuple[WrittenPointer[FutexNode],
                                      WrittenPointer[RobustListHead]]:
        robust_list_entry = await sem.ptr(FutexNode(None, Int32(futex_value)))
        robust_list_head = await sem.ptr(RobustListHead(robust_list_entry))
        return robust_list_entry, robust_list_head
    robust_list_entry, robust_list_head = await ram.perform_batch(op, allocator)
    await task.set_robust_list(robust_list_head)
    return robust_list_entry

async def setup_shared_memory_robust_futex(
        parent: Thread,
        parent_memfd: FileDescriptor,
        child: Thread,
        child_memfd: FileDescriptor,
) -> t.Tuple[WrittenPointer[FutexNode], WrittenPointer[FutexNode]]:
    """Setup a robust futex in `child` which is in shared memory with `parent`

    Since it's in shared memory, that means parent can do a futex_wait on it. To
    achieve this shared memory behavior, we need to be passed two memfds which
    should point to the same memory.

    We map the memfds in the parent and child, set up the robust futex in the
    child, translate the resulting pointer to the parent's address space, and
    return (parent futex pointer, child futex pointer)

    """
    # resize memfd appropriately
    size = 4096
    await parent_memfd.ftruncate(size)
    file = near.File()
    # set up parent mapping
    parent_mapping = await parent_memfd.mmap(size, PROT.READ|PROT.WRITE, MAP.SHARED, file=file)
    await parent_memfd.close()
    # set up child mapping
    child_mapping = await child_memfd.mmap(size, PROT.READ|PROT.WRITE, MAP.SHARED, file=file)
    await child_memfd.close()

    # setup the child task's futex list
    child_futex_node = await set_singleton_robust_futex(
        child.task, child.ram, memory.Arena(child_mapping))
    # translate the futex from the child's address space to the parent's address space
    parent_futex_node = child_futex_node._with_mapping(parent_mapping)
    return parent_futex_node, child_futex_node

@dataclass
class RsyscallServerExecutable:
    """A standalone representation of the rsyscall-server executable

    This is not really a user-facing class, it exists just to promote modularity. With
    this class, rsyscall_exec needs only to take an object of this type, rather than look
    up the location of rsyscall-server itself; therefore we can add new ways to look up
    executables and create this class without having to teach rsyscall_exec about them.

    """
    command: Command

    @classmethod
    async def from_store(cls, store: nix.Store) -> RsyscallServerExecutable:
        rsyscall_path = await store.realise(nix.rsyscall)
        server = Command(rsyscall_path/"libexec"/"rsyscall"/"rsyscall-server", ['rsyscall-server'], {})
        return cls(server)

async def rsyscall_exec(
        parent: Thread,
        child: ChildThread,
        executable: RsyscallServerExecutable,
    ) -> None:
    """exec rsyscall-server and repair the thread to continue working after the exec

    This is of fairly limited use except as a stress-test for our primitives.

    We need to know about our parent thread because we need to create a new futex child
    process to wait for the child calling exec. We can't have the child itself create this
    futex process because the whole point of the futex process is to monitor for the child
    calling exec or exit; see ChildSyscallInterface. That futex process can be a child of
    anyone, so technically `parent` doesn't have to be our parent, it just needs to
    currently share its fd table with us.

    For the new futex process, we need to use a robust futex, registered on the
    robust_list.  The robust_list is, unfortunately, the only truly robust way to get
    notified of a process calling exec. We use ctid elsewhere, but the kernel has an
    irritating check where it only does a futex wakeup on ctid if the process's memory
    space is shared. The kernel always does the robust_list wakeups, so we can rely on the
    robust list even when we're working with processes that don't share address space.

    """
    [(access_data_sock, passed_data_sock)] = await child.open_async_channels(1)
    # create this guy and pass him down to the new thread
    child_futex_memfd = await child.task.memfd_create(
        await child.ram.ptr(Path("child_robust_futex_list")))
    parent_futex_memfd = child_futex_memfd.for_task(parent.task)
    if isinstance(child.task.sysif, ChildSyscallInterface):
        syscall = child.task.sysif
    else:
        raise Exception("can only exec in ChildSyscallInterface sysifs, not", child.task.sysif)
    # unshare files so we can unset cloexec on fds to inherit
    await child.unshare_files(going_to_exec=True)
    # unset cloexec on all the fds we want to copy to the new space
    for fd in child.task.fd_handles:
        await fd.fcntl(F.SETFD, 0)
    def encode(fd: FileDescriptor) -> bytes:
        return str(int(fd.near)).encode()
    #### call exec and set up the new task
    await child.exec(executable.command.args(
        encode(passed_data_sock), encode(syscall.infd), encode(syscall.outfd),
        *[encode(fd) for fd in child.task.fd_handles],
    ), [child.monitor.sigfd.signal_block])
    if len(syscall.rsyscall_connection.pending_responses) == 1:
        # remove execve from pending_responses, we're never going to get a response to it
        syscall.rsyscall_connection.pending_responses = []
    else:
        raise Exception("syscall connection in bad state; " +
                        "expected one pending response for execve, instead got",
                        syscall.rsyscall_connection.pending_responses)
    # a new address space needs a new allocator and transport; we mutate the RAM so things
    # that have stored the RAM continue to work.
    child.ram.allocator = memory.AllocatorClient.make_allocator(child.task)
    child.ram.transport = SocketMemoryTransport(
        access_data_sock, passed_data_sock, child.ram.allocator)
    # rsyscall-server will write the symbol table to passed_data_sock, and we'll read it
    # from access_data sock to set up the symbol table for the new address space
    child.loader = NativeLoader.make_from_symbols(
        child.task, await AsyncReadBuffer(access_data_sock).read_cffi('struct rsyscall_symbol_table'))

    #### make new futex process
    # The futex process we used before is dead now that we've exec'd. We need to make some
    # syscalls in the child to set up the new futex process. ChildSyscallInterface would
    # throw immediately on seeing the current dead futex_process, so we need to null it out.
    syscall.futex_process = None
    # We have to use a robust futex now for our futex_process, see docstring
    parent_futex_ptr, child_futex_ptr = await setup_shared_memory_robust_futex(
        parent, parent_futex_memfd, child, child_futex_memfd)
    syscall.futex_process = await launch_futex_monitor(
        parent.ram, parent.loader, parent.monitor, parent_futex_ptr)
    # now we are alive and fully working again, we can be used for GC
    child.task._add_to_active_fd_table_tasks()

async def spawn_exec(thread: Thread, store: nix.Store) -> ChildThread:
    "Fork off a new ChildThread and immediately call rsyscall_exec in it"
    executable = await RsyscallServerExecutable.from_store(store)
    child = await thread.fork()
    await rsyscall_exec(thread, child, executable)
    return child
