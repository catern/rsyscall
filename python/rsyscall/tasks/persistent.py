import typing as t
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import StandardTask
from rsyscall.path import Path
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.non_child import NonChildSyscallInterface
from rsyscall.tasks.fork import ChildSyscallInterface, spawn_child_task
from rsyscall.loader import NativeLoader, Trampoline
from rsyscall.sched import Stack
from rsyscall.handle import WrittenPointer, ThreadProcess, Pointer, Task, FileDescriptor
from rsyscall.memory.socket_transport import SocketMemoryTransport
import contextlib

import trio
import struct
from dataclasses import dataclass
import logging
import rsyscall.batch as batch

from rsyscall.memory.ram import RAM

from rsyscall.monitor import ChildProcessMonitor
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor

from rsyscall.struct import Bytes, Int32, StructList

from rsyscall.sched import CLONE
from rsyscall.sys.socket import AF, SOCK, Address, SendmsgFlags, SendMsghdr, CmsgSCMRights, CmsgList
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.uio import IovecList
from rsyscall.signal import Signals, Sigset, SignalBlock
from rsyscall.sys.prctl import PR

__all__ = [
    "fork_persistent",
]

@dataclass
class PersistentServer:
    """The tracking object for a task which can be made to live on after the main process exits.

    The model we currently use for this is:
    1. Create this can-be-persistent task
    2. Do a bunch of things in that task, allocating whatever resources
    3. Call make_persistent to make the task actually persistent
    4. Crash or disconnect, and call reconnect to reconnect.

    It would be better for the model to be:
    1. Do a bunch of things in whatever task you like, allocating whatever resources
    2. Create an immediately persistent task which inherits those resources
    3. Crash or disconnect, and call reconnect to reconnect.

    However, the major obstacle is child processes. Child processes can't be inherited to a new
    child task, much less passed around between unrelated tasks like file descriptors can.

    CLONE_THREAD allows creating a new child task which can wait on the child processes of the
    parent; however, CLONE_THREAD also does a bunch of other stuff which is undesirable. Among other
    things, CLONE_THREAD tasks:
    - don't send SIGCHLD when exiting so they can't be waited on without dedicating a thread to block in wait
    - don't leave a zombie when they die
    - block several unshare and setns operations
    - complicate signals and many other system calls

    While CLONE_THREAD could allow the better model for persistent tasks, it comes with a host of
    other disadvantages and complexities, so we're just biting the bullet and accepting the worse
    model. Hopefully some new functionality might come along which allows inheriting or moving child
    processes without these disadvantages.

    """
    path: Path
    task: Task
    ram: RAM
    listening_sock: FileDescriptor
    # saved to keep the reference to the stack pointer etc alive
    thread_process: t.Optional[ThreadProcess] = None
    transport: t.Optional[SocketMemoryTransport] = None

    async def _connect_and_send(self, stdtask: StandardTask, fds: t.List[FileDescriptor]) -> t.List[FileDescriptor]:
        sock = await stdtask.make_afd(await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK, 0), nonblock=True)
        sockaddr_un = await SockaddrUn.from_path(stdtask, self.path)
        def sendmsg_op(sem: batch.BatchSemantics) -> t.Tuple[
                WrittenPointer[Address], WrittenPointer[Int32], WrittenPointer[SendMsghdr], Pointer[StructList[Int32]]]:
            addr: WrittenPointer[Address] = sem.to_pointer(sockaddr_un)
            count = sem.to_pointer(Int32(len(fds)))
            iovec = sem.to_pointer(IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(CmsgList([CmsgSCMRights(fds)]))
            hdr = sem.to_pointer(SendMsghdr(None, iovec, cmsgs))
            response_buf = sem.to_pointer(StructList(Int32, [Int32(0)]*len(fds)))
            return addr, count, hdr, response_buf
        addr, count, hdr, response = await stdtask.ram.perform_batch(sendmsg_op)
        data = None
        async with contextlib.AsyncExitStack() as stack:
            if isinstance(self.task.sysif, ChildSyscallInterface):
                await stack.enter_async_context(self.task.sysif._throw_on_child_exit())
            await sock.connect(addr)
            _, _ = await sock.write(count)
            _, [] = await sock.handle.sendmsg(hdr, SendmsgFlags.NONE)
            while response.bytesize() > 0:
                valid, response = await sock.read(response)
                data += valid
        if data is None:
            return []
        remote_fds = [self.task.make_fd_handle(near.FileDescriptor(int(i)))
                      for i in (await data.read()).elems]
        await sock.close()
        return remote_fds

    async def make_persistent(self) -> None:
        await self.task.unshare_files()
        if not isinstance(self.task.sysif, (ChildSyscallInterface, NonChildSyscallInterface)):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        new_sysif = NonChildSyscallInterface(self.task.sysif.rsyscall_connection, self.task.process.near)
        new_sysif.store_remote_side_handles(self.task.sysif.infd, self.task.sysif.outfd)
        self.task.sysif = new_sysif
        await self.task.setsid()
        await self.task.prctl(PR.SET_PDEATHSIG, 0)

    async def reconnect(self, stdtask: StandardTask) -> None:
        self.listening_sock.validate()
        await handle.run_fd_table_gc(self.task.fd_table)
        if not isinstance(self.task.sysif, (ChildSyscallInterface, NonChildSyscallInterface)):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        await self.task.sysif.close_interface()
        # TODO should check that no transport requests are in flight
        if self.transport is not None:
            await self.transport.local.close()
        [(access_syscall_sock, syscall_sock), (access_data_sock, data_sock)] = await stdtask.open_async_channels(2)
        [infd, outfd, remote_data_sock] = await self._connect_and_send(
            stdtask, [syscall_sock, syscall_sock, data_sock])
        await syscall_sock.close()
        await data_sock.close()
        # update the syscall and transport with new connections
        self.task.sysif.rsyscall_connection = SyscallConnection(access_syscall_sock, access_syscall_sock)
        self.task.sysif.store_remote_side_handles(infd, outfd)
        # TODO technically this could still be in the same address space - that's the case in our tests.
        # we should figure out a way to use a LocalMemoryTransport here so it can copy efficiently
        transport = SocketMemoryTransport(access_data_sock, remote_data_sock, self.ram.allocator)
        self.ram.transport = transport
        self.transport = transport
        # close remote fds we don't have handles to; this includes the old interface fds.
        await handle.run_fd_table_gc(self.task.fd_table)

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def fork_persistent(
        self: StandardTask, path: Path,
) -> t.Tuple[StandardTask, PersistentServer]:
    listening_sock = await self.task.socket(AF.UNIX, SOCK.STREAM)
    await listening_sock.bind(await self.ram.to_pointer(await SockaddrUn.from_path(self, path)))
    await listening_sock.listen(1)
    [(access_sock, remote_sock)] = await self.open_async_channels(1)
    task = await spawn_child_task(
        self.task, self.ram, self.loader, self.child_monitor,
        access_sock, remote_sock,
        Trampoline(self.loader.persistent_server_func, [remote_sock, remote_sock, listening_sock]),
        newuser=False, newpid=False, fs=True, sighand=True)
    listening_sock_handle = listening_sock.move(task)
    ram = RAM(task, self.ram.transport.inherit(task), self.ram.allocator.inherit(task))

    ## create the new persistent task
    epoller = await EpollCenter.make_root(ram, task)
    signal_block = SignalBlock(task, await ram.to_pointer(Sigset({Signals.SIGCHLD})))
    # TODO use an inherited signalfd instead
    child_monitor = await ChildProcessMonitor.make(ram, task, epoller, signal_block=signal_block)
    stdtask = StandardTask(
        task, ram,
        self.connection.for_task(task, ram),
        self.loader,
        epoller,
        child_monitor,
        self.environ.inherit(task, ram),
        stdin=self.stdin.for_task(task),
        stdout=self.stdout.for_task(task),
        stderr=self.stderr.for_task(task),
    )
    persistent_server = PersistentServer(path, task, ram, listening_sock_handle)
    return stdtask, persistent_server
