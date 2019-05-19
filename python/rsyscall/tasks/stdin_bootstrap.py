import typing as t
from dataclasses import dataclass
from rsyscall.batch import BatchSemantics
from rsyscall.command import Command
from rsyscall.environ import Environment
from rsyscall.epoller import Epoller, AsyncReadBuffer
from rsyscall.handle import WrittenPointer, Task
from rsyscall.thread import Thread
from rsyscall.loader import NativeLoader
from rsyscall.memory.ram import RAM
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.struct import Bytes
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.non_child import NonChildSyscallInterface
import logging
import rsyscall.far as far
import rsyscall.memory.allocator as memory
import rsyscall.near as near
import rsyscall.nix as nix
import struct
import trio

from rsyscall.path import Path
from rsyscall.sched import CLONE
from rsyscall.signal import Signals, SignalBlock
from rsyscall.sys.memfd import MFD
from rsyscall.sys.socket import SOCK, AF, SendmsgFlags, FDPair, SendMsghdr, CmsgList, CmsgSCMRights
from rsyscall.sys.uio import IovecList

__all__ = [
    "stdin_bootstrap_path_from_store",
    "rsyscall_stdin_bootstrap",
]

async def stdin_bootstrap_path_from_store(store: nix.Store) -> Path:
    """Get the path to the rsyscall-stdin-bootstrap executable.

    We return a Path rather than a Command because the typical usage
    of this path will be to pass it as an argument to some other
    command, such as sudo.

    """
    rsyscall_path = await store.realise(nix.rsyscall)
    return rsyscall_path/"libexec"/"rsyscall"/"rsyscall-stdin-bootstrap"

async def rsyscall_stdin_bootstrap(
        parent: Thread,
        bootstrap_command: Command,
) -> t.Tuple[AsyncChildProcess, Thread]:
    """Fork and run an arbitrary Command which will start rsyscall_stdin_bootstrap"""
    #### fork and exec into the bootstrap command
    child = await parent.fork()
    # create the socketpair that will be used as stdin
    stdin_pair = await (await parent.task.socketpair(
        AF.UNIX, SOCK.STREAM, 0, await parent.ram.malloc_struct(FDPair))).read()
    parent_sock = stdin_pair.first
    child_sock = stdin_pair.second.move(child.task)
    # set up stdin with socketpair
    await child.unshare_files(going_to_exec=True)
    await child.stdin.replace_with(child_sock)
    # exec
    child_process = await child.exec(bootstrap_command)
    #### set up all the fds we'll want to pass over
    # the basic connections
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await parent.open_async_channels(2)
    # memfd for setting up the futex
    futex_memfd = await parent.task.memfd_create(
        await parent.ram.to_pointer(Path("child_robust_futex_list")), MFD.CLOEXEC)
    # send the fds to the new process
    connection_fd, make_connection = await parent.connection.prep_fd_transfer()
    def sendmsg_op(sem: BatchSemantics) -> WrittenPointer[SendMsghdr]:
        iovec = sem.to_pointer(IovecList([sem.malloc_type(Bytes, 1)]))
        cmsgs = sem.to_pointer(CmsgList([CmsgSCMRights([
            passed_syscall_sock, passed_data_sock, futex_memfd, connection_fd])]))
        return sem.to_pointer(SendMsghdr(None, iovec, cmsgs))
    _, [] = await parent_sock.sendmsg(await parent.ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
    # close our reference to fds that only the new process needs
    await passed_syscall_sock.close()
    await passed_data_sock.close()
    # close the socketpair
    await parent_sock.close()
    #### read describe to get all the information we need from the new process
    describe_buf = AsyncReadBuffer(access_data_sock)
    describe_struct = await describe_buf.read_cffi('struct rsyscall_stdin_bootstrap')
    environ = await describe_buf.read_envp(describe_struct.envp_count)
    #### build the new task
    pid = describe_struct.pid
    fd_table = far.FDTable(pid)
    address_space = far.AddressSpace(pid)
    fs_information = far.FSInformation(pid)
    # we assume pid namespace is shared
    pidns = parent.task.pidns
    # we assume net namespace is shared
    # TODO include namespace inode numbers numbers in describe
    # note: if we start dealing with namespace numbers then we need to
    # have a Kernel namespace which tells us which kernel we get those
    # numbers from.
    # oh hey we can conveniently dump the inode numbers with getdents!
    netns = parent.task.netns
    process = far.Process(pidns, near.Process(pid))
    remote_syscall_fd = near.FileDescriptor(describe_struct.syscall_fd)
    syscall = NonChildSyscallInterface(SyscallConnection(access_syscall_sock, access_syscall_sock), process.near)
    base_task = Task(syscall, process.near, None, fd_table, address_space, fs_information, pidns, netns)
    handle_remote_syscall_fd = base_task.make_fd_handle(remote_syscall_fd)
    syscall.store_remote_side_handles(handle_remote_syscall_fd, handle_remote_syscall_fd)
    allocator = memory.AllocatorClient.make_allocator(base_task)
    # we assume our SignalMask is zero'd before being started, so we don't inherit it
    ram = RAM(base_task,
               SocketMemoryTransport(access_data_sock,
                                     base_task.make_fd_handle(near.FileDescriptor(describe_struct.data_fd)),
                                     allocator),
               allocator)
    # TODO I think I can maybe elide creating this epollcenter and instead inherit it or share it, maybe?
    epoller = await Epoller.make_root(ram, base_task)
    child_monitor = await ChildProcessMonitor.make(ram, base_task, epoller)
    connection = make_connection(base_task, ram,
                                 base_task.make_fd_handle(near.FileDescriptor(describe_struct.connecting_fd)))
    new_parent = Thread(
        task=base_task,
        ram=ram,
        connection=connection,
        loader=NativeLoader.make_from_symbols(base_task, describe_struct.symbols),
        epoller=epoller,
        child_monitor=child_monitor,
        environ=Environment(base_task, ram, environ),
        stdin=base_task.make_fd_handle(near.FileDescriptor(0)),
        stdout=base_task.make_fd_handle(near.FileDescriptor(1)),
        stderr=base_task.make_fd_handle(near.FileDescriptor(2)),
    )
    #### TODO set up futex I guess
    remote_futex_memfd = near.FileDescriptor(describe_struct.futex_memfd)
    return child_process, new_parent
