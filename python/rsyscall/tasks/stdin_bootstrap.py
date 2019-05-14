import typing as t
import rsyscall.io as rsc
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import StandardTask, Path, SocketMemoryTransport, AsyncFileDescriptor, SignalBlock, ChildProcessMonitor, Command, AsyncReadBuffer
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.non_child import NonChildSyscallInterface
from rsyscall.loader import NativeLoader
import trio
import struct
from dataclasses import dataclass
import logging
import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess
from rsyscall.environ import Environment
from rsyscall.epoller import EpollCenter

import rsyscall.nix as nix
import rsyscall.batch as batch
from rsyscall.struct import Bytes

from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF, SendmsgFlags
from rsyscall.sys.memfd import MFD
from rsyscall.signal import Signals
from rsyscall.handle import FDPair

__all__ = [
    "stdin_bootstrap_path_from_store",
    "rsyscall_stdin_bootstrap",
]

async def stdin_bootstrap_path_from_store(store: nix.Store) -> Path:
    rsyscall_path = await store.realise(nix.rsyscall)
    return rsyscall_path/"libexec"/"rsyscall"/"rsyscall-stdin-bootstrap"

async def rsyscall_stdin_bootstrap(
        stdtask: StandardTask,
        bootstrap_command: Command,
) -> t.Tuple[AsyncChildProcess, StandardTask]:
    """Fork and run an arbitrary Command which will start rsyscall_stdin_bootstrap"""
    #### fork and exec into the bootstrap command
    thread = await stdtask.fork()
    # create the socketpair that will be used as stdin
    stdin_pair = await (await stdtask.task.base.socketpair(
        AF.UNIX, SOCK.STREAM, 0, await stdtask.ram.malloc_struct(FDPair))).read()
    parent_sock = stdin_pair.first
    child_sock = stdin_pair.second.move(thread.stdtask.task.base)
    # set up stdin with socketpair
    await thread.stdtask.unshare_files(going_to_exec=True)
    await thread.stdtask.stdin.replace_with(child_sock)
    # exec
    child_task = await thread.exec(bootstrap_command)
    #### set up all the fds we'll want to pass over
    # the basic connections
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await stdtask.open_async_channels(2)
    # memfd for setting up the futex
    futex_memfd = await stdtask.task.base.memfd_create(
        await stdtask.ram.to_pointer(handle.Path("child_robust_futex_list")), MFD.CLOEXEC)
    # send the fds to the new process
    connection_fd, make_connection = await stdtask.connection.prep_fd_transfer()
    def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.SendMsghdr]:
        iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
        cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([
            passed_syscall_sock, passed_data_sock, futex_memfd, connection_fd])]))
        return sem.to_pointer(handle.SendMsghdr(None, iovec, cmsgs))
    _, [] = await parent_sock.sendmsg(await stdtask.ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
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
    pidns = stdtask.task.base.pidns
    # we assume net namespace is shared
    # TODO include namespace inode numbers numbers in describe
    # note: if we start dealing with namespace numbers then we need to
    # have a Kernel namespace which tells us which kernel we get those
    # numbers from.
    # oh hey we can conveniently dump the inode numbers with getdents!
    netns = stdtask.task.base.netns
    process = far.Process(pidns, near.Process(pid))
    remote_syscall_fd = near.FileDescriptor(describe_struct.syscall_fd)
    syscall = NonChildSyscallInterface(SyscallConnection(access_syscall_sock, access_syscall_sock), process.near)
    base_task = handle.Task(syscall, process.near, None, fd_table, address_space, fs_information, pidns, netns)
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
    epoller = await EpollCenter.make_root(ram, base_task)
    child_monitor = await ChildProcessMonitor.make(ram, base_task, epoller)
    connection = make_connection(base_task, ram,
                                 base_task.make_fd_handle(near.FileDescriptor(describe_struct.connecting_fd)))
    new_stdtask = StandardTask(
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
    return child_task, new_stdtask
