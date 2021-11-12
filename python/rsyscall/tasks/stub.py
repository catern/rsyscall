"""A stub which can be launched by unrelated programs, which connects back to us

We create a StubServer, which listens on a Unix socket.

Then we arrange for other programs to launch rsyscall-unix-stub,
under an arbitrary executable name and with arbitrary arguments,
either with the RSYSCALL_UNIX_STUB_SOCK environment variable set or
through a wrapper shell script which sets RSYSCALL_UNIX_STUB_SOCK.

rsyscall-unix-stub will connect back to us over the Unix socket, and
we can call accept() to get a Thread which controls the
rsyscall-unix-stub, along with the command line arguments passed to
rsyscall-unix-stub, including the executable name.

At no point does the other program need to know that it is launching
the stub, nor does it have to be related to us in any way, other than
sharing enough of the mount table for the stub to connect back to the
Unix socket.

We can use these stubs to "mock" other programs. For example, we
could mock sendmail by putting a wrapper shell script named "sendmail"
on the PATH of some other program; then that program will run the stub
with stdin pointing to some email message and some command line
arguments. We call accept() and receive those arguments and a Thread
with that stdin, and we can do whatever we want with it.

We can make an analogy to the concept of a callback. In many
programming languages, we can pass a callback to other modules, and
when we're called we have complete control and we can choose what to
do and what to return. The stub is our way to pass a callback to
another program.

"""
from __future__ import annotations
import typing as t
import os
import rsyscall.near.types as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.thread import Thread
from rsyscall.tasks.connection import SyscallConnection
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

import rsyscall.struct
from rsyscall.environ import Environment
from rsyscall.handle import WrittenPointer, FileDescriptor, Task

from rsyscall.path import Path
from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF, SendmsgFlags, SendMsghdr, CmsgList, CmsgSCMRights
from rsyscall.sys.mman import MFD
from rsyscall.sys.uio import IovecList
from rsyscall.sys.un import SockaddrUn
from rsyscall.signal import SIG, Sigset, SignalBlock
from rsyscall.fcntl import O

__all__ = [
    "StubServer",
]

logger = logging.getLogger(__name__)

@dataclass
class StubServer:
    "A server which can be connected back to by rsyscall-unix-stub."
    listening_sock: AsyncFileDescriptor
    thread: Thread

    @classmethod
    async def listen_on(cls, thread: Thread, path: Path) -> StubServer:
        "Start listening on the passed-in path for stub connections."
        sockfd = await thread.make_afd(await thread.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        addr = await thread.ram.ptr(await SockaddrUn.from_path(thread, path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        return StubServer(sockfd, thread)

    @classmethod
    async def make(cls, thread: Thread, dir: Path, name: str) -> StubServer:
        "In the passed-in dir, make a listening stub server and an executable to connect to it."
        import rsyscall._nixdeps.librsyscall
        rsyscall_path = await nix.deploy(thread, rsyscall._nixdeps.librsyscall.closure)
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
        """Accept new connection and bootstrap over it; returns the stub's argv and the new thread

        The optional argument "thread" allows choosing what thread handles the bootstrap;
        by default we'll use the thread embedded in the StubServer.

        """
        if thread is None:
            thread = self.thread
        conn = await self.listening_sock.accept()
        argv, new_thread = await _setup_stub(thread, conn)
        # have to drop first argument, which is the unix_stub executable; see StubServer.make
        return argv[1:], new_thread

async def _setup_stub(
        thread: Thread,
        bootstrap_sock: FileDescriptor,
) -> t.Tuple[t.List[str], Thread]:
    "Setup a stub thread"
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await thread.open_async_channels(2)
    # memfd for setting up the futex
    futex_memfd = await thread.task.memfd_create(
        await thread.ram.ptr(Path("child_robust_futex_list")))
    # send the fds to the new process
    connection_fd, make_connection = await thread.connection.prep_fd_transfer()
    async def sendmsg_op(sem: RAM) -> WrittenPointer[SendMsghdr]:
        iovec = await sem.ptr(IovecList([await sem.malloc(bytes, 1)]))
        cmsgs = await sem.ptr(CmsgList([CmsgSCMRights([
            passed_syscall_sock, passed_data_sock, futex_memfd, connection_fd])]))
        return await sem.ptr(SendMsghdr(None, iovec, cmsgs))
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
    fd_table = handle.FDTable(pid)
    address_space = far.AddressSpace(pid)
    # we assume pid namespace is shared
    pidns = thread.task.pidns
    process = near.Process(pid)
    # we assume net namespace is shared - that's dubious...
    # we should make it possible to control the namespace sharing more, hmm.
    # TODO maybe the describe should contain the net namespace number? and we can store our own as well?
    # then we can automatically do it right
    base_task = Task(process, fd_table, address_space, pidns)
    remote_syscall_fd = base_task.make_fd_handle(near.FileDescriptor(describe_struct.syscall_fd))
    base_task.sysif = SyscallConnection(
        logger.getChild(str(process)),
        access_syscall_sock, access_syscall_sock,
        remote_syscall_fd, remote_syscall_fd,
    )
    allocator = memory.AllocatorClient.make_allocator(base_task)
    base_task.sigmask = Sigset({SIG(bit) for bit in rsyscall.struct.bits(describe_struct.sigmask)})
    ram = RAM(base_task,
              SocketMemoryTransport(access_data_sock,
                                    base_task.make_fd_handle(near.FileDescriptor(describe_struct.data_fd))),
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
        environ=Environment.make_from_environ(base_task, ram, environ),
        stdin=base_task.make_fd_handle(near.FileDescriptor(0)),
        stdout=base_task.make_fd_handle(near.FileDescriptor(1)),
        stderr=base_task.make_fd_handle(near.FileDescriptor(2)),
    )
    #### TODO set up futex I guess
    remote_futex_memfd = near.FileDescriptor(describe_struct.futex_memfd)
    return argv, new_thread
