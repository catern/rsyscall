from __future__ import annotations
import typing as t
import os
import rsyscall.near as near
import rsyscall.far as far
from rsyscall.thread import Thread
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.non_child import NonChildSyscallInterface
from rsyscall.loader import NativeLoader
import trio
from dataclasses import dataclass
import logging
import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM
import rsyscall.nix as nix
from rsyscall.epoller import Epoller, AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.monitor import ChildProcessMonitor
from rsyscall.command import Command
from rsyscall.memory.socket_transport import SocketMemoryTransport

import rsyscall.batch as batch
import rsyscall.struct
from rsyscall.environ import Environment
from rsyscall.handle import WrittenPointer, FileDescriptor, Task

from rsyscall.path import Path
from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF, Address, SendmsgFlags, SendMsghdr, CmsgList, CmsgSCMRights
from rsyscall.sys.memfd import MFD
from rsyscall.sys.uio import IovecList
from rsyscall.sys.un import SockaddrUn
from rsyscall.signal import Signals, Sigset, SignalBlock
from rsyscall.fcntl import O

__all__ = [
    "StubServer",
]

@dataclass
class StubServer:
    listening_sock: AsyncFileDescriptor
    thread: Thread

    @classmethod
    async def listen_on(cls, thread: Thread, path: Path) -> StubServer:
        "Start listening on the passed-in path for stub connections."
        sockfd = await thread.make_afd(
            await thread.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
        addr: WrittenPointer[Address] = await thread.ram.to_pointer(await SockaddrUn.from_path(thread, path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        return StubServer(sockfd, thread)

    @classmethod
    async def make(cls, thread: Thread, store: nix.Store, dir: Path, name: str) -> StubServer:
        "In the passed-in dir, make a listening stub server and an executable to connect to it."
        rsyscall_path = await store.realise(nix.rsyscall)
        stub_path = rsyscall_path/"libexec"/"rsyscall"/"rsyscall-unix-stub"
        sock_path = dir/f'{name}.sock'
        server = await StubServer.listen_on(thread, sock_path)
        # there's no POSIX sh way to set $0, so we'll pass $0 as $1, $1 as $2, etc.
        # $0 will be the stub executable, so we'll need to drop $0 in StubServer.
        wrapper = """#!/bin/sh
RSYSCALL_UNIX_STUB_SOCK_PATH={sock} exec {bin} "$0" "$@"
""".format(sock=os.fsdecode(sock_path), bin=os.fsdecode(stub_path))
        await thread.spit(dir/name, wrapper, mode=0o755)
        return server

    async def accept(self, thread: Thread=None) -> t.Tuple[t.List[str], Thread]:
        if thread is None:
            thread = self.thread
        conn = await self.listening_sock.accept()
        argv, new_thread = await _setup_stub(thread, conn)
        # have to drop first argument, which is the unix_stub executable; see make_stub
        return argv[1:], new_thread

async def _setup_stub(
        thread: Thread,
        bootstrap_sock: FileDescriptor,
) -> t.Tuple[t.List[str], Thread]:
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await thread.open_async_channels(2)
    # memfd for setting up the futex
    futex_memfd = await thread.task.memfd_create(
        await thread.ram.to_pointer(Path("child_robust_futex_list")))
    # send the fds to the new process
    connection_fd, make_connection = await thread.connection.prep_fd_transfer()
    async def sendmsg_op(sem: batch.BatchSemantics) -> WrittenPointer[SendMsghdr]:
        iovec = await sem.to_pointer(IovecList([await sem.malloc(bytes, 1)]))
        cmsgs = await sem.to_pointer(CmsgList([CmsgSCMRights([
            passed_syscall_sock, passed_data_sock, futex_memfd, connection_fd])]))
        return await sem.to_pointer(SendMsghdr(None, iovec, cmsgs))
    _, [] = await bootstrap_sock.sendmsg(await thread.ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
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
    # we assume pid namespace is shared
    pidns = thread.task.pidns
    process = near.Process(pid)
    # we assume net namespace is shared - that's dubious...
    # we should make it possible to control the namespace sharing more, hmm.
    # TODO maybe the describe should contain the net namespace number? and we can store our own as well?
    # then we can automatically do it right
    remote_syscall_fd = near.FileDescriptor(describe_struct.syscall_fd)
    syscall = NonChildSyscallInterface(SyscallConnection(access_syscall_sock, access_syscall_sock), process)
    base_task = Task(syscall, process, None, fd_table, address_space, pidns)
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
    epoller = await Epoller.make_root(ram, base_task)
    child_monitor = await ChildProcessMonitor.make(ram, base_task, epoller)
    connection = make_connection(base_task, ram,
                                 base_task.make_fd_handle(near.FileDescriptor(describe_struct.connecting_fd)))
    new_thread = Thread(
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
    return argv, new_thread
