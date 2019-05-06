from __future__ import annotations
import rsyscall.handle as handle
import rsyscall.base as base
import rsyscall.near as near
import rsyscall.memory.allocator as memory
from rsyscall.io import RsyscallThread, AsyncReadBuffer, ChildProcess, launch_futex_monitor, ProcessResources, StandardTask, SocketMemoryTransport, Command
import typing as t
from rsyscall.handle import WrittenPointer
from rsyscall.handle import FutexNode
import rsyscall.batch as batch
import rsyscall.nix as nix
from dataclasses import dataclass

from rsyscall.fcntl import F
from rsyscall.struct import Int32
from rsyscall.linux.futex import FUTEX_WAITERS, FUTEX_TID_MASK
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.memfd import MFD

async def set_singleton_robust_futex(
        task: handle.Task, transport: base.MemoryTransport, allocator: memory.AllocatorInterface,
) -> WrittenPointer[handle.FutexNode]:
    # have to set the futex pointer to this nonsense or the kernel won't wake on it properly
    futex_value = FUTEX_WAITERS|(int(task.process.near) & FUTEX_TID_MASK)
    def op(sem: batch.BatchSemantics) -> t.Tuple[WrittenPointer[handle.FutexNode],
                                                 WrittenPointer[handle.RobustListHead]]:
        robust_list_entry = sem.to_pointer(handle.FutexNode(None, Int32(futex_value)))
        robust_list_head = sem.to_pointer(handle.RobustListHead(robust_list_entry))
        return robust_list_entry, robust_list_head
    robust_list_entry, robust_list_head = await batch.perform_batch(task, transport, allocator, op)
    await task.set_robust_list(robust_list_head)
    return robust_list_entry

async def make_robust_futex_task(
        parent_stdtask: StandardTask,
        parent_memfd: handle.FileDescriptor,
        child_stdtask: StandardTask,
        child_memfd: handle.FileDescriptor,
) -> t.Tuple[ChildProcess, handle.Pointer[FutexNode], handle.MemoryMapping]:
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

    remote_futex_node = await set_singleton_robust_futex(
        child_stdtask.task.base, child_stdtask.task.transport, memory.Arena(remote_mapping))
    local_futex_node = remote_futex_node._with_mapping(local_mapping)
    # now we start the futex monitor
    futex_task = await launch_futex_monitor(
        parent_stdtask.task, parent_stdtask.process, parent_stdtask.child_monitor, local_futex_node)
    return futex_task, local_futex_node, remote_mapping

@dataclass
class RsyscallServerExecutable:
    command: Command

    @classmethod
    async def from_store(cls, store: nix.Store) -> RsyscallServerExecutable:
        rsyscall_path = await store.realise(nix.rsyscall)
        server = Command(rsyscall_path.handle/"libexec"/"rsyscall"/"rsyscall-server", ['rsyscall-server'], {})
        return cls(server)

async def rsyscall_exec(
        parent_stdtask: StandardTask,
        rsyscall_thread: RsyscallThread,
        executable: RsyscallServerExecutable,
    ) -> None:
    "Exec into the standalone rsyscall_server executable"
    stdtask = rsyscall_thread.stdtask
    [(access_data_sock, passed_data_sock)] = await stdtask.make_async_connections(1)
    # create this guy and pass him down to the new thread
    child_futex_memfd = await stdtask.task.base.memfd_create(
        await stdtask.task.to_pointer(handle.Path("child_robust_futex_list")), MFD.CLOEXEC)
    parent_futex_memfd = parent_stdtask.task.base.make_fd_handle(child_futex_memfd)
    syscall: ChildConnection = stdtask.task.base.sysif # type: ignore
    def encode(fd: near.FileDescriptor) -> bytes:
        return str(int(fd)).encode()
    async def do_unshare(close_in_old_space: t.List[near.FileDescriptor],
                         copy_to_new_space: t.List[near.FileDescriptor]) -> None:
        # unset cloexec on all the fds we want to copy to the new space
        for copying_fd in copy_to_new_space:
            await near.fcntl(syscall, copying_fd, F.SETFD, 0)
        child_task = await rsyscall_thread.exec(executable.command.args(
                encode(passed_data_sock.near), encode(syscall.infd.near), encode(syscall.outfd.near),
                *[encode(fd) for fd in copy_to_new_space],
            ), [stdtask.child_monitor.internal.signal_queue.signal_block])
        #### read symbols from describe fd
        describe_buf = AsyncReadBuffer(access_data_sock)
        symbol_struct = await describe_buf.read_cffi('struct rsyscall_symbol_table')
        stdtask.process = ProcessResources.make_from_symbols(stdtask.task.base, symbol_struct)
        # the futex task we used before is dead now that we've exec'd, have
        # to null it out
        syscall.futex_task = None
        # TODO maybe remove dependence on parent task for closing?
        for fd in close_in_old_space:
            await near.close(parent_stdtask.task.base.sysif, fd)
        stdtask.task.base.address_space = base.AddressSpace(rsyscall_thread.stdtask.task.base.process.near.id)
        # we mutate the allocator instead of replacing to so that anything that
        # has stored the allocator continues to work
        stdtask.task.allocator.allocator = memory.Allocator(stdtask.task.base)
        stdtask.task.transport = SocketMemoryTransport(access_data_sock, stdtask.access_task,
                                                       passed_data_sock)
    await stdtask.task.base.unshare_files(do_unshare)

    #### make new futex task
    futex_task, local_futex_node, remote_mapping = await make_robust_futex_task(
        parent_stdtask, parent_futex_memfd, stdtask, child_futex_memfd)
    # TODO how do we unmap the remote mapping?
    syscall.futex_task = futex_task

async def spawn_exec(self: StandardTask, store: nix.Store) -> RsyscallThread:
    executable = await RsyscallServerExecutable.from_store(store)
    rsyscall_thread = await self.fork()
    await rsyscall_exec(self, rsyscall_thread, executable)
    return rsyscall_thread