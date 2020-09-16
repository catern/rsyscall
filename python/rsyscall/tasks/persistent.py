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
from __future__ import annotations
import typing as t
import rsyscall.near.types as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.thread import Thread
from rsyscall.tasks.base_sysif import ConnectionSyscallInterface
from rsyscall.tasks.connection import SyscallConnection, ConnectionDefunctOnlyOnEOF
from rsyscall.tasks.clone import clone_child_task
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
from rsyscall.sys.socket import AF, SOCK, SendmsgFlags, SendMsghdr, CmsgSCMRights, CmsgList
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.uio import IovecList
from rsyscall.signal import SIG, Sigset, SignalBlock
from rsyscall.sys.prctl import PR

__all__ = [
    "clone_persistent",
    "PersistentThread",
]

logger = logging.getLogger(__name__)

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def clone_persistent(
        parent: Thread, path: t.Union[str, os.PathLike],
) -> PersistentThread:
    """Create a new not-yet-persistent thread and return the thread and its tracking object

    To make the thread actually persistent, you must call PersistentServer.make_persistent().

    The point of this hoop-jumping is just to prevent unnecessary resource leakage, so you
    can set up things in a persistent thread and only make it persistent when you're
    actually ready.

    A persistent thread is essentially the same as a normal thread, just running a
    different function. As such, it starts off sharing its file descriptor table and
    everything else with its parent thread. It's only when we disconnect and reconnect
    that it changes behavior.

    """
    listening_sock = await parent.task.socket(AF.UNIX, SOCK.STREAM)
    await listening_sock.bind(await parent.ram.ptr(await SockaddrUn.from_path(parent, path)))
    await listening_sock.listen(1)
    child_process, task = await clone_child_task(
        parent, CLONE.FILES|CLONE.FS|CLONE.SIGHAND,
        lambda sock: Trampoline(parent.loader.persistent_server_func, [sock, sock, listening_sock]))
    listening_sock_handle = listening_sock.move(task)
    ram = RAM(task, parent.ram.transport, parent.ram.allocator.inherit(task))

    ## create the new persistent task
    epoller = await Epoller.make_root(ram, task)
    signal_block = SignalBlock(task, await ram.ptr(Sigset({SIG.CHLD})))
    # TODO use an inherited signalfd instead
    child_monitor = await ChildProcessMonitor.make(ram, task, epoller, signal_block=signal_block)
    return PersistentThread(Thread(
        task, ram,
        parent.connection.inherit(task, ram),
        parent.loader,
        epoller,
        child_monitor,
        parent.environ.inherit(task, ram),
        stdin=parent.stdin.for_task(task),
        stdout=parent.stdout.for_task(task),
        stderr=parent.stderr.for_task(task),
    ), persistent_path=path, persistent_sock=listening_sock_handle)

async def _connect_and_send(self: PersistentThread, thread: Thread, fds: t.List[FileDescriptor]) -> t.List[FileDescriptor]:
    """Connect to a persistent thread's socket, send some file descriptors

    This isn't actually a generic function; the persistent thread expects exactly three
    file descriptors, and uses them in a special way.

    """
    sock = await thread.make_afd(await thread.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK, 0), nonblock=True)
    sockaddr_un = await SockaddrUn.from_path(thread, self.persistent_path)
    async def sendmsg_op(sem: RAM) -> t.Tuple[
            WrittenPointer[SockaddrUn], WrittenPointer[Int32], WrittenPointer[SendMsghdr], Pointer[StructList[Int32]]]:
        addr = await sem.ptr(sockaddr_un)
        count = await sem.ptr(Int32(len(fds)))
        iovec = await sem.ptr(IovecList([await sem.malloc(bytes, 1)]))
        cmsgs = await sem.ptr(CmsgList([CmsgSCMRights(fds)]))
        hdr = await sem.ptr(SendMsghdr(None, iovec, cmsgs))
        response_buf = await sem.ptr(StructList(Int32, [Int32(0)]*len(fds)))
        return addr, count, hdr, response_buf
    addr, count, hdr, response = await thread.ram.perform_batch(sendmsg_op)
    data = None
    async with self.task.sysif.rsyscall_connection.defunct_monitor.throw_on_connection_defunct():
        await sock.connect(addr)
        _, _ = await sock.write(count)
        _, [] = await sock.handle.sendmsg(hdr, SendmsgFlags.NONE)
        while response.size() > 0:
            valid, response = await sock.read(response)
            data += valid
    remote_fds = [self.task.make_fd_handle(near.FileDescriptor(int(i)))
                  for i in ((await data.read()).elems if data else [])]
    await sock.close()
    return remote_fds
    
class PersistentThread(Thread):
    """A thread which can live on even if everything else has exited

    It's not persistent by default - you need to call make_persistent() first to make that
    happen. After that, this thread will continue living even if its parent dies or our
    connection to it fails, and you can reconnect to it by calling reconnect(thr), passing
    the thread you want to initiate the connection from.

    A great name for this would be "daemon thread", but that's already taken by more
    conventional thread systems to refer to a much more conventional kind of thread.  I
    wistfully recall the name I gave to a previous attempt at making a hosting system for
    long-running tasks: daemon engines. That was a great name.

    """
    def __init__(self,
                 thread: Thread,
                 persistent_path: t.Union[str, os.PathLike],
                 persistent_sock: FileDescriptor,
    ) -> None:
        super()._init_from(thread)
        self.persistent_path = persistent_path
        self.persistent_sock = persistent_sock

    async def make_persistent(self) -> None:
        "Make this thread actually persistent"
        # TODO hmm should we switch the transport?
        # i guess we aren't actually doing anything but rearranging the file descriptors
        await self.unshare_files(going_to_exec=False)
        if not isinstance(self.task.sysif, ConnectionSyscallInterface):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        self.task.sysif.rsyscall_connection.defunct_monitor = ConnectionDefunctOnlyOnEOF()
        new_sysif = ConnectionSyscallInterface(
            self.task.sysif.rsyscall_connection, logger.getChild(str(self.task.process.near)))
        new_sysif.store_remote_side_handles(self.task.sysif.infd, self.task.sysif.outfd)
        self.task.sysif = new_sysif
        await self.task.setsid()
        await self.task.prctl(PR.SET_PDEATHSIG, 0)

    async def reconnect(self, thread: Thread) -> None:
        """Using the passed-in thread to establish the connection, reconnect to this PersistentThread

        """
        await self.task.run_fd_table_gc(use_self=False)
        if not isinstance(self.task.sysif, ConnectionSyscallInterface):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        await self.task.sysif.close_interface()
        # TODO should check that no transport requests are in flight
        [(access_syscall_sock, syscall_sock), (access_data_sock, data_sock)] = await thread.open_async_channels(2)
        [infd, outfd, remote_data_sock] = await _connect_and_send(self, thread, [syscall_sock, syscall_sock, data_sock])
        await syscall_sock.close()
        await data_sock.close()
        # Fix up Task's sysif with new SyscallConnection
        self.task.sysif.rsyscall_connection = SyscallConnection(
            access_syscall_sock, access_syscall_sock, self.task.sysif.rsyscall_connection.defunct_monitor)
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
        await self.task.run_fd_table_gc()
