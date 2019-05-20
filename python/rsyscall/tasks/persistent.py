import typing as t
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.thread import Thread
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
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.sys.epoll import EPOLL

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
    epoller: Epoller
    listening_sock: FileDescriptor
    # saved to keep the reference to the stack pointer etc alive
    thread_process: t.Optional[ThreadProcess] = None
    transport: t.Optional[SocketMemoryTransport] = None

    async def _connect_and_send(self, thread: Thread, fds: t.List[FileDescriptor]) -> t.List[FileDescriptor]:
        sock = await thread.make_afd(await thread.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK, 0), nonblock=True)
        sockaddr_un = await SockaddrUn.from_path(thread, self.path)
        async def sendmsg_op(sem: batch.BatchSemantics) -> t.Tuple[
                WrittenPointer[Address], WrittenPointer[Int32], WrittenPointer[SendMsghdr], Pointer[StructList[Int32]]]:
            addr: WrittenPointer[Address] = await sem.to_pointer(sockaddr_un)
            count = await sem.to_pointer(Int32(len(fds)))
            iovec = await sem.to_pointer(IovecList([await sem.malloc_type(Bytes, 1)]))
            cmsgs = await sem.to_pointer(CmsgList([CmsgSCMRights(fds)]))
            hdr = await sem.to_pointer(SendMsghdr(None, iovec, cmsgs))
            response_buf = await sem.to_pointer(StructList(Int32, [Int32(0)]*len(fds)))
            return addr, count, hdr, response_buf
        addr, count, hdr, response = await thread.ram.perform_batch(sendmsg_op)
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

    async def reconnect(self, thread: Thread) -> None:
        self.listening_sock.validate()
        await handle.run_fd_table_gc(self.task.fd_table)
        if not isinstance(self.task.sysif, (ChildSyscallInterface, NonChildSyscallInterface)):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        await self.task.sysif.close_interface()
        # TODO should check that no transport requests are in flight
        if self.transport is not None:
            await self.transport.local.close()
        [(access_syscall_sock, syscall_sock), (access_data_sock, data_sock)] = await thread.open_async_channels(2)
        [infd, outfd, remote_data_sock] = await self._connect_and_send(
            thread, [syscall_sock, syscall_sock, data_sock])
        await syscall_sock.close()
        await data_sock.close()
        # Fix up Task's sysif with new SyscallConnection
        self.task.sysif.rsyscall_connection = SyscallConnection(access_syscall_sock, access_syscall_sock)
        self.task.sysif.store_remote_side_handles(infd, outfd)
        # Fix up RAM with new transport
        # TODO technically this could still be in the same address space - that's the case in our tests.
        # we should figure out a way to use a LocalMemoryTransport here so it can copy efficiently
        transport = SocketMemoryTransport(access_data_sock, remote_data_sock, self.ram.allocator)
        self.ram.transport = transport
        self.transport = transport
        # Fix up epoller with new activity fd
        await self.epoller.register(infd, EPOLL.IN|EPOLL.OUT|EPOLL.RDHUP|EPOLL.PRI|EPOLL.ERR|EPOLL.HUP)
        # close remote fds we don't have handles to; this includes the old interface fds.
        await handle.run_fd_table_gc(self.task.fd_table)

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def fork_persistent(
        parent: Thread, path: Path,
) -> t.Tuple[Thread, PersistentServer]:
    listening_sock = await parent.task.socket(AF.UNIX, SOCK.STREAM)
    await listening_sock.bind(await parent.ram.to_pointer(await SockaddrUn.from_path(parent, path)))
    await listening_sock.listen(1)
    [(access_sock, remote_sock)] = await parent.open_async_channels(1)
    task = await spawn_child_task(
        parent.task, parent.ram, parent.loader, parent.child_monitor,
        access_sock, remote_sock,
        Trampoline(parent.loader.persistent_server_func, [remote_sock, remote_sock, listening_sock]),
        CLONE.FS|CLONE.SIGHAND)
    listening_sock_handle = listening_sock.move(task)
    ram = RAM(task, parent.ram.transport, parent.ram.allocator.inherit(task))

    ## create the new persistent task
    epoller = await Epoller.make_root(ram, task)
    signal_block = SignalBlock(task, await ram.to_pointer(Sigset({Signals.SIGCHLD})))
    # TODO use an inherited signalfd instead
    child_monitor = await ChildProcessMonitor.make(ram, task, epoller, signal_block=signal_block)
    child = Thread(
        task, ram,
        parent.connection.for_task(task, ram),
        parent.loader,
        epoller,
        child_monitor,
        parent.environ.inherit(task, ram),
        stdin=parent.stdin.for_task(task),
        stdout=parent.stdout.for_task(task),
        stderr=parent.stderr.for_task(task),
    )
    persistent_server = PersistentServer(path, task, ram, epoller, listening_sock_handle)
    return child, persistent_server
