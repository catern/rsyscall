"""A stub which can be launched by unrelated programs, which connects back to us

We create a StubServer, which listens on a Unix socket.

Then we arrange for other programs to launch rsyscall-unix-stub,
under an arbitrary executable name and with arbitrary arguments,
either with the RSYSCALL_UNIX_STUB_SOCK environment variable set or
through a wrapper shell script which sets RSYSCALL_UNIX_STUB_SOCK.

rsyscall-unix-stub will connect back to us over the Unix socket, and
we can call accept() to get a Process which controls the
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
arguments. We call accept() and receive those arguments and a Process
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
from rsyscall.thread import Process
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.loader import NativeLoader
import trio
from dataclasses import dataclass
import logging
import rsyscall.memory.allocator as memory
import rsyscall.nix as nix
from rsyscall.epoller import Epoller, AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.monitor import ChildPidMonitor
from rsyscall.command import Command

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
    process: Process

    @classmethod
    async def listen_on(cls, process: Process, path: Path) -> StubServer:
        "Start listening on the passed-in path for stub connections."
        sockfd = await process.make_afd(await process.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        addr = await process.task.ptr(await SockaddrUn.from_path(process, path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        return StubServer(sockfd, process)

    @classmethod
    async def make(cls, process: Process, dir: Path, name: str) -> StubServer:
        "In the passed-in dir, make a listening stub server and an executable to connect to it."
        import rsyscall._nixdeps.librsyscall
        rsyscall_path = await nix.deploy(process, rsyscall._nixdeps.librsyscall.closure)
        stub_path = rsyscall_path/"libexec"/"rsyscall"/"rsyscall-unix-stub"
        sock_path = dir/f'{name}.sock'
        server = await StubServer.listen_on(process, sock_path)
        # there's no POSIX sh way to set $0, so we'll pass $0 as $1, $1 as $2, etc.
        # $0 will be the stub executable, so we'll need to drop $0 in StubServer.
        wrapper = """#!/bin/sh
RSYSCALL_UNIX_STUB_SOCK_PATH={sock} exec {bin} "$0" "$@"
""".format(sock=os.fsdecode(sock_path), bin=os.fsdecode(stub_path))
        await process.spit(dir/name, wrapper, mode=0o755)
        return server

    async def accept(self, process: Process=None) -> t.Tuple[t.List[str], Process]:
        """Accept new connection and bootstrap over it; returns the stub's argv and the new process

        The optional argument "process" allows choosing what process handles the bootstrap;
        by default we'll use the process embedded in the StubServer.

        """
        if process is None:
            process = self.process
        conn = await self.listening_sock.accept()
        argv, new_process = await _setup_stub(process, conn)
        # have to drop first argument, which is the unix_stub executable; see StubServer.make
        return argv[1:], new_process

async def _setup_stub(
        process: Process,
        bootstrap_sock: FileDescriptor,
) -> t.Tuple[t.List[str], Process]:
    "Setup a stub process"
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await process.open_async_channels(2)
    # memfd for setting up the futex
    futex_memfd = await process.task.memfd_create(
        await process.task.ptr(Path("child_robust_futex_list")))
    # send the fds to the new process
    connection_fd, make_connection = await process.connection.prep_fd_transfer()
    iovec = await process.ptr(IovecList([await process.malloc(bytes, 1)]))
    cmsgs = await process.ptr(CmsgList([CmsgSCMRights([
        passed_syscall_sock, passed_data_sock, futex_memfd, connection_fd])]))
    _, [] = await bootstrap_sock.sendmsg(await process.ptr(SendMsghdr(None, iovec, cmsgs)), SendmsgFlags.NONE)
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
    pidns = process.task.pidns
    # we assume mount namespace is not shared (won't hurt)
    mountns = far.MountNamespace(pid)
    pid = near.Pid(pid)
    # we assume net namespace is shared - that's dubious...
    # we should make it possible to control the namespace sharing more, hmm.
    # TODO maybe the describe should contain the net namespace number? and we can store our own as well?
    # then we can automatically do it right
    base_task = Task(pid, fd_table, address_space, pidns, mountns)
    remote_syscall_fd = base_task.make_fd_handle(near.FileDescriptor(describe_struct.syscall_fd))
    base_task.sysif = SyscallConnection(
        logger.getChild(str(pid)),
        access_syscall_sock,
        remote_syscall_fd,
    )
    base_task.allocator = await memory.AllocatorClient.make_allocator(base_task)
    base_task.sigmask = Sigset({SIG(bit) for bit in rsyscall.struct.bits(describe_struct.sigmask)})
    # TODO I think I can maybe elide creating this epollcenter and instead inherit it or share it, maybe?
    # I guess I need to write out the set too in describe
    epoller = await Epoller.make_root(base_task)
    child_monitor = await ChildPidMonitor.make(base_task, epoller)
    connection = make_connection(base_task,
                                 base_task.make_fd_handle(near.FileDescriptor(describe_struct.connecting_fd)))
    new_process = Process(
        task=base_task,
        connection=connection,
        loader=NativeLoader.make_from_symbols(base_task, describe_struct.symbols),
        epoller=epoller,
        child_monitor=child_monitor,
        environ=Environment.make_from_environ(base_task, environ),
        stdin=base_task.make_fd_handle(near.FileDescriptor(0)),
        stdout=base_task.make_fd_handle(near.FileDescriptor(1)),
        stderr=base_task.make_fd_handle(near.FileDescriptor(2)),
    )
    #### TODO set up futex I guess
    remote_futex_memfd = near.FileDescriptor(describe_struct.futex_memfd)
    return argv, new_process
