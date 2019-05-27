from __future__ import annotations
from dataclasses import dataclass
from rsyscall.command import Command
from rsyscall.epoller import AsyncReadBuffer
from rsyscall.handle import WrittenPointer, Pointer, MemoryTransport, Task, FileDescriptor, MemoryMapping
from rsyscall.thread import ChildThread, Thread
from rsyscall.loader import NativeLoader
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.monitor import AsyncChildProcess
from rsyscall.tasks.fork import launch_futex_monitor, ChildSyscallInterface, SyscallConnection
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
    # have to set the futex pointer to this nonsense or the kernel won't wake on it properly
    futex_value = FUTEX_WAITERS|(int(task.process.near) & FUTEX_TID_MASK)
    async def op(sem: RAM) -> t.Tuple[WrittenPointer[FutexNode],
                                                 WrittenPointer[RobustListHead]]:
        robust_list_entry = await sem.ptr(FutexNode(None, Int32(futex_value)))
        robust_list_head = await sem.ptr(RobustListHead(robust_list_entry))
        return robust_list_entry, robust_list_head
    robust_list_entry, robust_list_head = await ram.perform_batch(op, allocator)
    await task.set_robust_list(robust_list_head)
    return robust_list_entry

async def make_robust_futex_process(
        parent: Thread,
        parent_memfd: FileDescriptor,
        child: Thread,
        child_memfd: FileDescriptor,
) -> t.Tuple[AsyncChildProcess, Pointer[FutexNode], MemoryMapping]:
    # resize memfd appropriately
    futex_memfd_size = 4096
    await parent_memfd.ftruncate(futex_memfd_size)
    file = near.File()
    # set up local mapping
    local_mapping = await parent_memfd.mmap(futex_memfd_size, PROT.READ|PROT.WRITE, MAP.SHARED, file=file)
    await parent_memfd.invalidate()
    # set up remote mapping
    remote_mapping = await child_memfd.mmap(futex_memfd_size, PROT.READ|PROT.WRITE, MAP.SHARED, file=file)
    await child_memfd.invalidate()

    remote_futex_node = await set_singleton_robust_futex(child.task, child.ram, memory.Arena(remote_mapping))
    local_futex_node = remote_futex_node._with_mapping(local_mapping)
    # now we start the futex monitor
    futex_process = await launch_futex_monitor(
        parent.ram, parent.loader, parent.monitor, local_futex_node)
    return futex_process, local_futex_node, remote_mapping

@dataclass
class RsyscallServerExecutable:
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
    "Exec into the standalone rsyscall_server executable"
    [(access_data_sock, passed_data_sock)] = await child.open_async_channels(1)
    # create this guy and pass him down to the new thread
    child_futex_memfd = await child.task.memfd_create(
        await child.ram.ptr(Path("child_robust_futex_list")))
    parent_futex_memfd = parent.task.make_fd_handle(child_futex_memfd)
    if isinstance(child.task.sysif, ChildSyscallInterface):
        syscall = child.task.sysif
    else:
        raise Exception("can only exec in ChildSyscallInterface sysifs, not",
                        child.task.sysif)
    if not isinstance(child.ram.allocator, memory.AllocatorClient):
        raise Exception("can only exec in AllocatorClient RAMs, not",
                        child.ram.allocator)
    # unshare files so we can unset cloexec on fds to inherit
    await child.unshare_files(going_to_exec=True)
    child.task.manipulating_fd_table = True
    # unset cloexec on all the fds we want to copy to the new space
    for fd in child.task.fd_handles:
        await fd.fcntl(F.SETFD, 0)
    def encode(fd: near.FileDescriptor) -> bytes:
        return str(int(fd)).encode()
    # TODO we're just leaking this, I guess?
    child_process = await child.exec(executable.command.args(
            encode(passed_data_sock.near), encode(syscall.infd.near), encode(syscall.outfd.near),
            *[encode(fd.near) for fd in child.task.fd_handles],
    ), [child.monitor.sigfd.signal_block])
    #### read symbols from describe fd
    describe_buf = AsyncReadBuffer(access_data_sock)
    symbol_struct = await describe_buf.read_cffi('struct rsyscall_symbol_table')
    child.loader = NativeLoader.make_from_symbols(child.task, symbol_struct)
    # the futex task we used before is dead now that we've exec'd, have
    # to null it out
    syscall.futex_process = None
    # the old RC would wait forever for the exec to complete; we need to make a new one.
    syscall.rsyscall_connection = SyscallConnection(syscall.rsyscall_connection.tofd, syscall.rsyscall_connection.fromfd)
    child.task.address_space = far.AddressSpace(child.task.process.near.id)
    # we mutate the allocator instead of replacing to so that anything that
    # has stored the allocator continues to work
    child.ram.allocator.allocator = memory.Allocator(child.task)
    child.ram.transport = SocketMemoryTransport(access_data_sock,
                                                  passed_data_sock, child.ram.allocator)
    child.task.manipulating_fd_table = False

    #### make new futex task
    futex_process, local_futex_node, remote_mapping = await make_robust_futex_process(
        parent, parent_futex_memfd, child, child_futex_memfd)
    # TODO how do we unmap the remote mapping?
    syscall.futex_process = futex_process
    child.task._add_to_active_fd_table_tasks()

async def spawn_exec(thread: Thread, store: nix.Store) -> ChildThread:
    executable = await RsyscallServerExecutable.from_store(store)
    child = await thread.fork()
    await rsyscall_exec(thread, child, executable)
    return child
