"""Persistent threads, which live on after their parent thread has died, and to which we can reconnect

These are threads which stick around, holding resources, even if we died or our connection
to them fails. We can reconnect to the persistent thread and continue to access all the
old resources.

After we disconnect from a persistent thread for whatever reason, it is left in an inert
state. It won't make any syscalls until we reconnect to it.

This is useful for fault isolation. To run and monitor long-running processes, we can and
should ourselves be long-running; but, we might crash at some point. The persistent thread
provides fault isolation: We may crash, but the thread and all its children will stay
alive, and we can reconnect to the thread after restarting and resume monitoring the
long-running processes. The persistent thread provides similar fault isolation for any
other resource that a thread might hold, such as file descriptors; the persistent thread
will keep file descriptors open even after we die.

The persistent thread doesn't provide any mechanism to recover information about the state
of the persistent thread, such as what child processes it has and what file descriptors it
has open. Therefore, we should arrange to have other state-persistence mechanism so that
we can recover our state if we crash. For example, we could maintain an on-disk database
where we log information about what processes we've started in what persistent threads,
and what the status of each of those processes is. Then we could recover information about
the state of the persistent thread from that database, reconnect to the persistent thread,
and resume normal operation.

That being said, a caveat: We don't currently have any logic to support recovering
information from such a database after a crash in a safe way. Such a database could be
created, but it would require creating resource handles in a way that is not guaranteed to
be safe. Determining a clean, generic way to persist information about the state of
resources in a way that can be safely recovered after a crash is an open question.


--------------------------------------------------------------------------------
CLONE_THREAD

The model we currently use for persistent threads is:
1. Create this can-be-persistent thread
2. Do a bunch of things in that thread, allocating whatever resources
3. Call make_persistent to make the thread actually persistent
4. Crash or disconnect, and call reconnect to reconnect.

It would be better for the model to be:
1. Do a bunch of things in whatever thread you like, allocating whatever resources
2. Create an immediately persistent thread which inherits those resources
3. Crash or disconnect, and call reconnect to reconnect.

However, the major obstacle is child processes. Child processes can't be inherited to a
new child process, much less passed around between unrelated processes like file
descriptors can.

CLONE_THREAD allows creating a new child process which can wait on the child processes of the
parent; however, CLONE_THREAD also does a bunch of other stuff which is undesirable. Among
other things, CLONE_THREAD processes:
- don't send SIGCHLD when exiting, so they can't be waited on without dedicating a thread
  to monitor them
- don't leave a zombie when they die
- block several unshare and setns operations
- complicate signals and many other system calls

While CLONE_THREAD could allow the better model for persistent threads, it comes with a
host of other disadvantages and complexities, so we're just biting the bullet and
accepting the worse model.

The recent feature of pidfds will likely allow a better model, once we're able to wait on
pidfds, which hasn't yet been added.

"""
import typing as t
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.thread import Thread
from rsyscall.path import Path
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.non_child import NonChildSyscallInterface
from rsyscall.tasks.fork import ChildSyscallInterface, clone_child_task
from rsyscall.loader import NativeLoader, Trampoline
from rsyscall.sched import Stack
from rsyscall.handle import WrittenPointer, ThreadProcess, Pointer, Task, FileDescriptor
from rsyscall.memory.socket_transport import SocketMemoryTransport
import contextlib

import trio
import struct
from dataclasses import dataclass
import logging
from rsyscall.memory.ram import RAM

from rsyscall.monitor import ChildProcessMonitor
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.sys.epoll import EPOLL

from rsyscall.struct import Int32, StructList

from rsyscall.sched import CLONE
from rsyscall.sys.socket import AF, SOCK, Address, SendmsgFlags, SendMsghdr, CmsgSCMRights, CmsgList
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.uio import IovecList
from rsyscall.signal import SIG, Sigset, SignalBlock
from rsyscall.sys.prctl import PR

__all__ = [
    "fork_persistent",
]

@dataclass
class PersistentServer:
    """The tracking object for a task which can be made to live on after the main process exits.

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
        async def sendmsg_op(sem: RAM) -> t.Tuple[
                WrittenPointer[Address], WrittenPointer[Int32], WrittenPointer[SendMsghdr], Pointer[StructList[Int32]]]:
            addr: WrittenPointer[Address] = await sem.ptr(sockaddr_un)
            count = await sem.ptr(Int32(len(fds)))
            iovec = await sem.ptr(IovecList([await sem.malloc(bytes, 1)]))
            cmsgs = await sem.ptr(CmsgList([CmsgSCMRights(fds)]))
            hdr = await sem.ptr(SendMsghdr(None, iovec, cmsgs))
            response_buf = await sem.ptr(StructList(Int32, [Int32(0)]*len(fds)))
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
        def devnull(event: EPOLL) -> None:
            pass
        await self.epoller.register(infd, EPOLL.IN|EPOLL.OUT|EPOLL.RDHUP|EPOLL.PRI|EPOLL.ERR|EPOLL.HUP,
                                    devnull)
        # close remote fds we don't have handles to; this includes the old interface fds.
        await handle.run_fd_table_gc(self.task.fd_table)

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def fork_persistent(
        parent: Thread, path: Path,
) -> t.Tuple[Thread, PersistentServer]:
    """Create a new not-yet-persistent thread and return the thread and its tracking object

    To make the thread persistent, you must call PersistentServer.make_persistent().
    This is just to prevent unnecessary resource leakage.

    A persistent thread is essentially the same as a normal thread, just running a
    different native function. As such, it starts off sharing its file descriptor table
    and everything else with its parent thread.

    """
    listening_sock = await parent.task.socket(AF.UNIX, SOCK.STREAM)
    await listening_sock.bind(await parent.ram.ptr(await SockaddrUn.from_path(parent, path)))
    await listening_sock.listen(1)
    child_process, task = await clone_child_task(
        parent, CLONE.FS|CLONE.SIGHAND,
        lambda sock: Trampoline(parent.loader.persistent_server_func, [sock, sock, listening_sock]))
    listening_sock_handle = listening_sock.move(task)
    ram = RAM(task, parent.ram.transport, parent.ram.allocator.inherit(task))

    ## create the new persistent task
    epoller = await Epoller.make_root(ram, task)
    signal_block = SignalBlock(task, await ram.ptr(Sigset({SIG.CHLD})))
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
