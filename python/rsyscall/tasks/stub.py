from __future__ import annotations
import typing as t
import os
import rsyscall.io as rsc
import rsyscall.base as base
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import RsyscallConnection, StandardTask, RsyscallInterface, Path, Task, SocketMemoryTransport, EpollWaiter, SyscallResponse, log_syscall, AsyncFileDescriptor, raise_if_error, ThreadMaker, FunctionPointer, CThread, SignalBlock, ChildProcessMonitor, ReadableWritableFile, robust_unix_bind, robust_unix_connect, Command, ChildProcess, AsyncReadBuffer, SignalMask, ProcessResources, FilesystemResources, UnixSocketFile, spit, FileDescriptor, ReadableFile, WritableFile
import rsyscall.memory_abstracted_syscalls as memsys
import trio
import struct
from dataclasses import dataclass
import logging
import rsyscall.memory as memory

from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF
from rsyscall.sys.memfd import MFD
from rsyscall.sys.un import SockaddrUn
from rsyscall.signal import Signals
from rsyscall.fcntl import O

@dataclass
class StubServer:
    listening_sock: AsyncFileDescriptor
    stdtask: StandardTask

    @classmethod
    async def listen_on(cls, stdtask: StandardTask, path: Path) -> StubServer:
        "Start listening on the passed-in path for stub connections."
        sockfd = await stdtask.task.socket_unix(SOCK.STREAM)
        await sockfd.bind(SockaddrUn.from_path(path))
        await sockfd.listen(10)
        asyncfd = await AsyncFileDescriptor.make(stdtask.epoller, sockfd)
        return StubServer(asyncfd, stdtask)

    @classmethod
    async def make(cls, stdtask: StandardTask, dir: Path, name: str) -> StubServer:
        "In the passed-in dir, make a listening stub server and an executable to connect to it."
        sock_path = dir/f'{name}.sock'
        server = await StubServer.listen_on(stdtask, sock_path)
        # there's no POSIX sh way to set $0, so we'll pass $0 as $1, $1 as $2, etc.
        # $0 will be the stub executable, so we'll need to drop $0 in StubServer.
        wrapper = """#!/bin/sh
    RSYSCALL_UNIX_STUB_SOCK_PATH={sock} exec {bin} "$0" "$@"
    """.format(sock=os.fsdecode(sock_path), bin=os.fsdecode(stdtask.filesystem.rsyscall_unix_stub_path))
        await spit(dir/name, wrapper, mode=0o755)
        return server

    async def accept(self, stdtask: StandardTask=None) -> t.Tuple[t.List[str], StandardTask]:
        if stdtask is None:
            stdtask = self.stdtask
        conn: FileDescriptor[UnixSocketFile]
        addr: SockaddrUn
        conn, addr = await self.listening_sock.accept(O.CLOEXEC) # type: ignore
        argv, new_stdtask = await setup_stub(stdtask, conn)
        # have to drop first argument, which is the unix_stub executable; see make_stub
        return argv[1:], new_stdtask

async def setup_stub(
        stdtask: StandardTask,
        bootstrap_sock: FileDescriptor[UnixSocketFile],
) -> t.Tuple[t.List[str], StandardTask]:
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await stdtask.make_async_connections(2)
    # memfd for setting up the futex
    futex_memfd = await memsys.memfd_create(
        stdtask.task.base, stdtask.task.transport, stdtask.task.allocator,
        b"child_robust_futex_list", MFD.CLOEXEC)
    # send the fds to the new process
    await memsys.sendmsg_fds(stdtask.task.base, stdtask.task.transport, stdtask.task.allocator, bootstrap_sock.handle.far,
                             [passed_syscall_sock.far, passed_data_sock.far,
                              futex_memfd, stdtask.connecting_connection[1].far])
    # close our reference to fds that only the new process needs
    await passed_syscall_sock.invalidate()
    await passed_data_sock.invalidate()
    # close the socketpair
    await bootstrap_sock.invalidate()
    #### read describe to get all the information we need from the new process
    describe_buf = AsyncReadBuffer(access_data_sock)
    describe_struct = await describe_buf.read_cffi('struct rsyscall_unix_stub')
    argv_raw = await describe_buf.read_length_prefixed_array(describe_struct.argc)
    argv = [os.fsdecode(arg) for arg in argv_raw]
    environ = await describe_buf.read_envp(describe_struct.envp_count)
    #### build the new task
    pid = describe_struct.pid
    fd_table = far.FDTable(pid)
    address_space = far.AddressSpace(pid)
    fs_information = far.FSInformation(pid)
    # we assume pid namespace is shared
    pidns = stdtask.task.base.pidns
    process = far.Process(pidns, near.Process(pid))
    # we assume net namespace is shared - that's dubious...
    # we should make it possible to control the namespace sharing more, hmm.
    # TODO maybe the describe should contain the net namespace number? and we can store our own as well?
    # then we can automatically do it right
    netns = stdtask.task.base.netns
    remote_syscall_fd = near.FileDescriptor(describe_struct.syscall_fd)
    syscall = RsyscallInterface(RsyscallConnection(access_syscall_sock, access_syscall_sock), process.near, remote_syscall_fd)
    base_task = base.Task(syscall, process, fd_table, address_space, fs_information, pidns, netns)
    handle_remote_syscall_fd = base_task.make_fd_handle(remote_syscall_fd)
    syscall.store_remote_side_handles(handle_remote_syscall_fd, handle_remote_syscall_fd)
    task = Task(base_task,
                SocketMemoryTransport(access_data_sock,
                                      base_task.make_fd_handle(near.FileDescriptor(describe_struct.data_fd)), None),
                memory.AllocatorClient.make_allocator(base_task),
                SignalMask({Signals(bit) for bit in memsys.bits(describe_struct.sigmask)}),
    )
    # TODO I think I can maybe elide creating this epollcenter and instead inherit it or share it, maybe?
    # I guess I need to write out the set too in describe
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
        process_resources=ProcessResources.make_from_symbols(address_space, describe_struct.symbols),
        filesystem_resources=FilesystemResources.make_from_environ(base_task, environ),
        epoller=epoller,
        child_monitor=child_monitor,
        environment=environ,
        stdin=task._make_fd(0, ReadableFile(shared=True)),
        stdout=task._make_fd(1, WritableFile(shared=True)),
        stderr=task._make_fd(2, WritableFile(shared=True)),
    )
    #### TODO set up futex I guess
    remote_futex_memfd = near.FileDescriptor(describe_struct.futex_memfd)
    return argv, new_stdtask
