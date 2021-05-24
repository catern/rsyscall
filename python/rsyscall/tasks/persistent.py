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

## `CLONE_THREAD`

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

`CLONE_THREAD` allows creating a new child process which can wait on the child processes of the
parent; however, `CLONE_THREAD` also does a bunch of other stuff which is undesirable. Among
other things, `CLONE_THREAD` processes:
- don't send `SIGCHLD` when exiting, so they can't be waited on without dedicating a thread
  to monitor them
- don't leave a zombie when they die
- block several unshare and setns operations
- complicate signals and many other system calls

While `CLONE_THREAD` could allow the better model for persistent threads, it comes with a
host of other disadvantages and complexities, so we're just biting the bullet and
accepting the worse model.

The recent feature of pidfds will likely allow a better model, once we're able to wait on
pidfds, which hasn't yet been added.

"""
from __future__ import annotations
from dneio import Continuation, shift
import typing as t
import rsyscall.near.types as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.thread import Thread
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.clone import clone_child_task
from rsyscall.loader import NativeLoader, Trampoline
from rsyscall.sched import Stack
from rsyscall.handle import WrittenPointer, ThreadProcess, Pointer, Task, FileDescriptor
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.near.sysif import SyscallInterface, SyscallSendError
from rsyscall.sys.syscall import SYS

import trio
import struct
import os
from dataclasses import dataclass
import logging
from rsyscall.memory.ram import RAM

from rsyscall.monitor import ChildProcessMonitor
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.sys.epoll import EPOLL

from rsyscall.struct import Int32, StructList

from rsyscall.sched import CLONE
from rsyscall.sys.socket import AF, SOCK, SendmsgFlags, SendMsghdr, CmsgSCMRights, CmsgList, SHUT
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.uio import IovecList
from rsyscall.signal import SIG, Sigset, SignalBlock
from rsyscall.sys.prctl import PR

__all__ = [
    "clone_persistent",
    "PersistentThread",
]

logger = logging.getLogger(__name__)

class PersistentSyscallConnection(SyscallInterface):
    def __init__(self, conn: SyscallConnection) -> None:
        self.conn: t.Optional[SyscallConnection] = conn
        self._activity_fd_conn: t.Optional[SyscallConnection] = conn
        self.logger = self.conn.logger
        self._new_conn_cbs: t.List[Continuation[SyscallConnection]] = []
        self._break_exc: t.Optional[SyscallSendError] = None
        self._break_cb: t.Optional[Continuation[SyscallSendError]] = None

    def wait_for_break_cb(self, cb: Continuation[SyscallSendError]) -> None:
        self._break_cb = cb

    async def wait_for_break(self) -> SyscallSendError:
        assert self._break_cb is None
        if self._break_exc:
            exc = self._break_exc
            self._break_exc = None
            return exc
        else:
            return await shift(self.wait_for_break_cb)

    def set_new_conn(self, conn: SyscallConnection) -> None:
        # to preserve the global relative ordering of syscalls,
        # we don't set self.conn again until syscalls stop appearing on self._new_conn_cbs
        # but we have to set activity_fd_conn because some callback might use get_activity_fd
        self._activity_fd_conn = conn
        while self._new_conn_cbs:
            cbs = self._new_conn_cbs
            self._new_conn_cbs = []
            for cb in cbs:
                cb.send(conn)
        self.conn = conn

    async def shutdown_current_connection(self) -> None:
        # Shut down write end of the current connection; any currently running or pending
        # syscalls (such as epoll_wait) will be able to finish and receive their response,
        # after which the syscall server will close its end of the current connection and
        # start listening for a new connection.
        if self.conn:
            await self.conn.tofd.handle.shutdown(SHUT.WR)

    async def close_interface(self) -> None:
        if self.conn:
            await self.conn.close_interface()

    def get_activity_fd(self) -> FileDescriptor:
        if self._activity_fd_conn:
            return self._activity_fd_conn.get_activity_fd()
        raise Exception("can't get activity fd while disconnected")

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        while True:
            if self.conn is None:
                conn = await shift(self._new_conn_cbs.append)
            else:
                conn = self.conn
            try:
                return await conn.syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
            except SyscallSendError as exc:
                if self.conn is conn:
                    self.conn = None
                    self._activity_fd_conn = None
                    if self._break_cb:
                        self._break_cb.send(exc)
                    else:
                        self._break_exc = exc

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
        parent.task, parent.ram, parent.connection, parent.loader, parent.monitor,
        CLONE.FILES|CLONE.FS|CLONE.SIGHAND,
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
    sock = await thread.make_afd(await thread.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
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
        self.prepped_for_reconnect = False

    async def prep_for_reconnect(self) -> None:
        # TODO hmm should we switch the transport?
        # i guess we aren't actually doing anything but rearranging the file descriptors
        await self.unshare_files(going_to_exec=False)
        if not isinstance(self.task.sysif, SyscallConnection):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        self.task.sysif = PersistentSyscallConnection(self.task.sysif)
        self.prepped_for_reconnect = True

    async def make_persistent(self) -> None:
        "Make this thread actually persistent"
        await self.prep_for_reconnect()
        await self.task.setsid()
        await self.task.prctl(PR.SET_PDEATHSIG, 0)

    async def reconnect(self, thread: Thread) -> None:
        """Using the passed-in thread to establish the connection, reconnect to this PersistentThread

        """
        if not self.prepped_for_reconnect:
            # It does work to reconnect without prep_for_reconnect, except for one nitpick:
            # If the underlying process for the PersistentThread dies while we're in the
            # middle of reconnecting to it, the file descriptors opened by the C code
            # running in the process will leak if the process is in a shared fd table.
            # That's annoying on its own, but also means we won't get an EOF from our
            # communication with the process, and we'll just hang forever.
            await self.prep_for_reconnect()
        await self.task.run_fd_table_gc(use_self=False)
        if not isinstance(self.task.sysif, PersistentSyscallConnection):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        await self.task.sysif.shutdown_current_connection()
        [(access_syscall_sock, syscall_sock), (access_data_sock, data_sock)] = await thread.open_async_channels(2)
        [infd, outfd, remote_data_sock] = await _connect_and_send(self, thread, [syscall_sock, syscall_sock, data_sock])
        await syscall_sock.close()
        await data_sock.close()
        # Set up the new SyscallConnection
        conn = SyscallConnection(
            self.task.sysif.logger,
            access_syscall_sock, access_syscall_sock,
            infd, outfd,
        )
        self.task.sysif.set_new_conn(conn)
        # Fix up RAM with new transport
        # TODO technically this could still be in the same address space - that's the case in our tests.
        # we should figure out a way to use a LocalMemoryTransport here so it can copy efficiently
        transport = SocketMemoryTransport(access_data_sock, remote_data_sock)
        self.ram.transport = transport
        self.transport = transport
        # close remote fds we don't have handles to; this includes the old interface fds.
        await self.task.run_fd_table_gc()
