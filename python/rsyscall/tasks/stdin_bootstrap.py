import typing as t
import rsyscall.io as rsc
import rsyscall.base as base
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import RsyscallConnection, StandardTask, RsyscallInterface, Path, Task, SocketMemoryTransport, EpollWaiter, SyscallResponse, log_syscall, AsyncFileDescriptor, raise_if_error, FunctionPointer, SignalBlock, ChildProcessMonitor, ReadableWritableFile, robust_unix_bind, robust_unix_connect, Command, ChildProcess, AsyncReadBuffer, SignalMask, ProcessResources, ReadableFile, WritableFile
import trio
import struct
from dataclasses import dataclass
import logging
import rsyscall.memory as memory

import rsyscall.nix as nix
import rsyscall.batch as batch
from rsyscall.struct import Bytes

from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF, SendmsgFlags
from rsyscall.sys.memfd import MFD
from rsyscall.signal import Signals

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
) -> t.Tuple[ChildProcess, StandardTask]:
    """Fork and run an arbitrary Command which will start rsyscall_stdin_bootstrap"""
    #### fork and exec into the bootstrap command
    thread = await stdtask.fork()
    # create the socketpair that will be used as stdin
    parent_sock, child_sock_parent = await stdtask.task.socketpair(AF.UNIX, SOCK.STREAM, 0)
    child_sock = child_sock_parent.move(thread.stdtask.task.base)
    # set up stdin with socketpair
    await thread.stdtask.unshare_files(going_to_exec=True)
    await thread.stdtask.stdin.replace_with(child_sock.handle)
    # exec
    child_task = await bootstrap_command.exec(thread)
    #### set up all the fds we'll want to pass over
    # the basic connections
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await stdtask.make_async_connections(2)
    # memfd for setting up the futex
    futex_memfd = await stdtask.task.base.memfd_create(
        await stdtask.task.to_pointer(handle.Path("child_robust_futex_list")), MFD.CLOEXEC)
    # send the fds to the new process
    def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.SendMsghdr]:
        iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
        cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([
            passed_syscall_sock, passed_data_sock, futex_memfd, stdtask.connecting_connection[1]])]))
        return sem.to_pointer(handle.SendMsghdr(None, iovec, cmsgs))
    _, [] = await parent_sock.handle.sendmsg(await stdtask.task.perform_batch(sendmsg_op), SendmsgFlags.NONE)
    # close our reference to fds that only the new process needs
    await passed_syscall_sock.invalidate()
    await passed_data_sock.invalidate()
    # close the socketpair
    await parent_sock.invalidate()
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
    syscall = RsyscallInterface(RsyscallConnection(access_syscall_sock, access_syscall_sock), process.near, remote_syscall_fd)
    base_task = base.Task(syscall, process.near, None, fd_table, address_space, fs_information, pidns, netns)
    handle_remote_syscall_fd = base_task.make_fd_handle(remote_syscall_fd)
    syscall.store_remote_side_handles(handle_remote_syscall_fd, handle_remote_syscall_fd)
    task = Task(base_task,
                SocketMemoryTransport(access_data_sock, stdtask.access_task,
                                      base_task.make_fd_handle(near.FileDescriptor(describe_struct.data_fd))),
                memory.AllocatorClient.make_allocator(base_task),
                SignalMask(set()),
    )
    # TODO I think I can maybe elide creating this epollcenter and instead inherit it or share it, maybe?
    epoller = await task.make_epoll_center()
    child_monitor = await ChildProcessMonitor.make(task, epoller)
    new_stdtask = StandardTask(
        access_task=stdtask.access_task,
        access_epoller=stdtask.access_epoller,
        access_connection=stdtask.access_connection,
        connecting_task=stdtask.connecting_task,
        connecting_connection=(stdtask.connecting_connection[0],
                               base_task.make_fd_handle(near.FileDescriptor(describe_struct.connecting_fd))),
        task=task,
        process_resources=ProcessResources.make_from_symbols(base_task, describe_struct.symbols),
        epoller=epoller,
        child_monitor=child_monitor,
        environment=environ,
        stdin=task._make_fd(0, ReadableFile(shared=True)),
        stdout=task._make_fd(1, WritableFile(shared=True)),
        stderr=task._make_fd(2, WritableFile(shared=True)),
    )
    #### TODO set up futex I guess
    remote_futex_memfd = near.FileDescriptor(describe_struct.futex_memfd)
    return child_task, new_stdtask
