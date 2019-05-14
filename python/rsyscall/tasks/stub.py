from __future__ import annotations
import typing as t
import os
import rsyscall.io as rsc
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import StandardTask
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.non_child import NonChildSyscallInterface
from rsyscall.loader import NativeLoader
import trio
from dataclasses import dataclass
import logging
import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM
import rsyscall.nix as nix
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.monitor import ChildProcessMonitor
from rsyscall.command import Command
from rsyscall.memory.socket_transport import SocketMemoryTransport

import rsyscall.batch as batch
from rsyscall.struct import Bytes
import rsyscall.struct
from rsyscall.environ import Environment
from rsyscall.handle import WrittenPointer

from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF, SendmsgFlags, Address
from rsyscall.sys.memfd import MFD
from rsyscall.sys.un import SockaddrUn
from rsyscall.signal import Signals, Sigset, SignalBlock
from rsyscall.fcntl import O

__all__ = [
    "StubServer",
]

@dataclass
class StubServer:
    listening_sock: AsyncFileDescriptor
    stdtask: StandardTask

    @classmethod
    async def listen_on(cls, stdtask: StandardTask, path: handle.Path) -> StubServer:
        "Start listening on the passed-in path for stub connections."
        sockfd = await stdtask.make_afd(
            await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
        addr: WrittenPointer[Address] = await stdtask.ram.to_pointer(await SockaddrUn.from_path(stdtask, path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        return StubServer(sockfd, stdtask)

    @classmethod
    async def make(cls, stdtask: StandardTask, store: nix.Store, dir: handle.Path, name: str) -> StubServer:
        "In the passed-in dir, make a listening stub server and an executable to connect to it."
        rsyscall_path = await store.realise(nix.rsyscall)
        stub_path = rsyscall_path/"libexec"/"rsyscall"/"rsyscall-unix-stub"
        sock_path = dir/f'{name}.sock'
        server = await StubServer.listen_on(stdtask, sock_path)
        # there's no POSIX sh way to set $0, so we'll pass $0 as $1, $1 as $2, etc.
        # $0 will be the stub executable, so we'll need to drop $0 in StubServer.
        wrapper = """#!/bin/sh
RSYSCALL_UNIX_STUB_SOCK_PATH={sock} exec {bin} "$0" "$@"
""".format(sock=os.fsdecode(sock_path), bin=os.fsdecode(stub_path))
        await stdtask.spit(dir/name, wrapper, mode=0o755)
        return server

    async def accept(self, stdtask: StandardTask=None) -> t.Tuple[t.List[str], StandardTask]:
        if stdtask is None:
            stdtask = self.stdtask
        conn, addr = await self.listening_sock.accept(SOCK.CLOEXEC)
        argv, new_stdtask = await _setup_stub(stdtask, conn)
        # have to drop first argument, which is the unix_stub executable; see make_stub
        return argv[1:], new_stdtask

async def _setup_stub(
        stdtask: StandardTask,
        bootstrap_sock: handle.FileDescriptor,
) -> t.Tuple[t.List[str], StandardTask]:
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
    _, [] = await bootstrap_sock.sendmsg(await stdtask.ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
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
    syscall = NonChildSyscallInterface(SyscallConnection(access_syscall_sock, access_syscall_sock), process.near)
    base_task = handle.Task(syscall, process.near, None, fd_table, address_space, fs_information, pidns, netns)
    handle_remote_syscall_fd = base_task.make_fd_handle(remote_syscall_fd)
    syscall.store_remote_side_handles(handle_remote_syscall_fd, handle_remote_syscall_fd)
    allocator = memory.AllocatorClient.make_allocator(base_task)
    base_task.sigmask = Sigset({Signals(bit) for bit in rsyscall.struct.bits(describe_struct.sigmask)})
    ram = RAM(base_task,
              SocketMemoryTransport(access_data_sock,
                                    base_task.make_fd_handle(near.FileDescriptor(describe_struct.data_fd)),
                                    allocator),
              allocator)
    # TODO I think I can maybe elide creating this epollcenter and instead inherit it or share it, maybe?
    # I guess I need to write out the set too in describe
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
    return argv, new_stdtask
