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
from rsyscall.handle import WrittenPointer, Pointer, Task, FileDescriptor
from rsyscall.thread import ChildThread, Thread
from rsyscall.loader import NativeLoader
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.monitor import AsyncChildProcess
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.memory.ram import RAM
from rsyscall.sys.mman import MemoryMapping
import logging
import rsyscall.far as far
import rsyscall.memory.allocator as memory
import rsyscall.far as far
import rsyscall.nix as nix
import typing as t

from rsyscall.fcntl import F
from rsyscall.struct import Int32
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.memfd import MFD
from rsyscall.sched import CLONE

__all__ = [
    "RsyscallServerExecutable",
    "spawn_exec",
    "rsyscall_exec",
]

logger = logging.getLogger(__name__)

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
        rsyscall_path = await store.realise(nix.import_nix_dep("rsyscall"))
        server = Command(rsyscall_path/"libexec"/"rsyscall"/"rsyscall-server", ['rsyscall-server'], {})
        return cls(server)

async def rsyscall_exec(
        child: ChildThread,
        executable: RsyscallServerExecutable,
    ) -> None:
    """exec rsyscall-server and repair the thread to continue working after the exec

    This is of fairly limited use except as a stress-test for our primitives.

    """
    [(access_data_sock, passed_data_sock),
     (access_syscall_sock, passed_syscall_sock)] = await child.open_async_channels(2)
    if isinstance(child.task.sysif, SyscallConnection):
        syscall = child.task.sysif
    else:
        raise Exception("can only exec in SyscallConnection sysifs, not", child.task.sysif)
    # unshare files so we can unset cloexec on fds to inherit
    await child.unshare_files(going_to_exec=True)
    # unset cloexec on all the fds we want to copy to the new space
    fds_to_not_inherit = set([syscall.server_infd, syscall.server_outfd])
    fds_to_inherit = [fd for fd in child.task.fd_handles if fd not in fds_to_not_inherit]
    for fd in fds_to_inherit:
        await fd.fcntl(F.SETFD, 0)
    def encode(fd: FileDescriptor) -> str:
        return str(int(fd))
    #### call exec and set up the new task
    await child.exec(executable.command.args(
        encode(passed_data_sock), encode(passed_syscall_sock), encode(passed_syscall_sock),
        *[encode(fd) for fd in fds_to_inherit],
    ), [child.monitor.sigfd.signal_block])
    # a new address space needs a new allocator and transport; we mutate the RAM so things
    # that have stored the RAM continue to work.
    child.ram.allocator = memory.AllocatorClient.make_allocator(child.task)
    child.ram.transport = SocketMemoryTransport(access_data_sock, passed_data_sock)
    # rsyscall-server will write the symbol table to passed_data_sock, and we'll read it
    # from access_data sock to set up the symbol table for the new address space
    child.loader = NativeLoader.make_from_symbols(
        child.task, await AsyncReadBuffer(access_data_sock).read_cffi('struct rsyscall_symbol_table'))
    child.task.sysif = SyscallConnection(
        logger.getChild(str(child.process.process.near)),
        access_syscall_sock, access_syscall_sock,
        passed_syscall_sock, passed_syscall_sock,
    )
    # now we are alive and fully working again, we can be used for GC
    child.task._add_to_active_fd_table_tasks()

async def spawn_exec(thread: Thread, store: nix.Store) -> ChildThread:
    "Clone off a new ChildThread and immediately call rsyscall_exec in it."
    executable = await RsyscallServerExecutable.from_store(store)
    child = await thread.clone(CLONE.FILES)
    await rsyscall_exec(child, executable)
    return child
