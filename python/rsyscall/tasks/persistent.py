"""Persistent processes, which live on after their parent process has died, and to which we can reconnect

These are processes which stick around, holding resources, even if we died or our connection
to them fails. We can reconnect to the persistent process and continue to access all the
old resources.

After we disconnect from a persistent process for whatever reason, it is left in an inert
state. It won't make any syscalls until we reconnect to it.

Any syscalls made while disconnected are blocked until we actually reconnect, at which point they're all sent.
`SyscallSendError` will never be thrown to user code by a persistent process; instead, the syscall will simply block.
However, `SyscallHangup` can be thrown, if the connection to a persistent process breaks while a syscall is in progress.
User code should retry after `SyscallHangup`;
we can't internally retry since we don't know if that's safe for a given syscall.

This is useful for fault isolation. To run and monitor long-running processes, we can and
should ourselves be long-running; but, we might crash at some point. The persistent process
provides fault isolation: We may crash, but the process and all its children will stay
alive, and we can reconnect to the process after restarting and resume monitoring the
long-running processes. The persistent process provides similar fault isolation for any
other resource that a process might hold, such as file descriptors; the persistent process
will keep file descriptors open even after we die.

The persistent process doesn't provide any mechanism to recover information about the state
of the persistent process, such as what child processes it has and what file descriptors it
has open. Therefore, we should arrange to have other state-persistence mechanism so that
we can recover our state if we crash. For example, we could maintain an on-disk database
where we log information about what processes we've started in what persistent processes,
and what the status of each of those processes is. Then we could recover information about
the state of the persistent process from that database, reconnect to the persistent process,
and resume normal operation.

That being said, a caveat: We don't currently have any logic to support recovering
information from such a database after a crash in a safe way. Such a database could be
created, but it would require creating resource handles in a way that is not guaranteed to
be safe. Determining a clean, generic way to persist information about the state of
resources in a way that can be safely recovered after a crash is an open question.

## `CLONE_THREAD`

The model we currently use for persistent processes is:

1. Create this can-be-persistent process
2. Do a bunch of things in that process, allocating whatever resources
3. Call make_persistent to make the process actually persistent
4. Crash or disconnect, and call reconnect to reconnect.

It would be better for the model to be:

1. Do a bunch of things in whatever process you like, allocating whatever resources
2. Create an immediately persistent process which inherits those resources
3. Crash or disconnect, and call reconnect to reconnect.

However, the major obstacle is child processes. Child processes can't be inherited to a
new child process, much less passed around between unrelated processes like file
descriptors can.

`CLONE_THREAD` allows creating a new child process which can wait on the child processes of the
parent; however, `CLONE_THREAD` also does a bunch of other stuff which is undesirable. Among
other things, `CLONE_THREAD` processes:
- don't send `SIGCHLD` when exiting, so they can't be waited on without dedicating a process
  to monitor them
- don't leave a zombie when they die
- block several unshare and setns operations
- complicate signals and many other system calls

While `CLONE_THREAD` could allow the better model for persistent processes, it comes with a
host of other disadvantages and complexities, so we're just biting the bullet and
accepting the worse model.

The recent feature of pidfds will likely allow a better model, once we're able to wait on
pidfds, which hasn't yet been added.

"""
from __future__ import annotations
from dneio import Continuation, shift, RequestQueue, reset
import typing as t
import rsyscall.near.types as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.thread import Process
from rsyscall.tasks.connection import SyscallConnection
from rsyscall.tasks.clone import clone_child_task
from rsyscall.loader import NativeLoader, Trampoline
from rsyscall.sched import Stack
from rsyscall.handle import WrittenPointer, ProcessPid, Pointer, Task, FileDescriptor
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.near.sysif import SyscallInterface, SyscallSendError
from rsyscall.sys.syscall import SYS

import trio
import struct
import os
from dataclasses import dataclass
import logging
from rsyscall.memory.ram import RAM

from rsyscall.monitor import ChildPidMonitor
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
    "PersistentProcess",
]

logger = logging.getLogger(__name__)

@dataclass
class Get:
    pass

@dataclass
class Broken:
    conn: SyscallConnection

@dataclass
class New:
    conn: SyscallConnection

class PersistentSyscallConnection(SyscallInterface):
    def __init__(self, conn: SyscallConnection) -> None:
        self._conn: t.Optional[SyscallConnection] = conn
        self.logger = self._conn.logger
        self.conn_queue: RequestQueue[t.Union[Get, Broken, New], t.Union[SyscallConnection, None]]  = RequestQueue()
        reset(self._run_conn_queue())

    async def set_new_conn(self, conn: SyscallConnection) -> None:
        await self.conn_queue.request(New(conn))

    async def shutdown_current_connection(self) -> None:
        # Shut down write end of the current connection; any currently running or pending
        # syscalls (such as epoll_wait) will be able to finish and receive their response,
        # after which the syscall server will close its end of the current connection and
        # start listening for a new connection.
        # We don't need to bother sequencing this with _run_conn_queue; it will be treated like the
        # connection spontaneously failing, which is something we want to be able to tolerate.
        if self._conn:
            await self._conn.fd.handle.shutdown(SHUT.WR)

    async def close_interface(self) -> None:
        if self._conn:
            await self._conn.close_interface()

    def get_activity_fd(self) -> FileDescriptor:
        if self._conn:
            return self._conn.get_activity_fd()
        raise Exception("can't get activity fd while disconnected")

    async def _run_conn_queue(self) -> None:
        while True:
            req, coro = await self.conn_queue.get_one()
            if isinstance(req, Get):
                coro.send(self._conn)
            elif isinstance(req, Broken):
                coro.send(None)
                if req.conn is self._conn:
                    # the current connection is broken
                    self._conn = None
                    # accumulate get requests until we get a new working connection
                    blocked_gets = []
                    while True:
                        req, coro = await self.conn_queue.get_one()
                        if isinstance(req, Get):
                            blocked_gets.append(coro)
                        elif isinstance(req, Broken):
                            # we will likely get multiple Broken requests when a connection breaks,
                            # from multiple syscalls. just ignore them.
                            coro.send(None)
                        else:
                            assert isinstance(req, New)
                            # it's important to set this here since some coro might use get_activity_fd.
                            self._conn = req.conn
                            coro.send(None)
                            # resume all the blocked get requests in the same order they were submitted;
                            # this preserves the sequencing of these syscalls, as required by SyscallInterface
                            for coro in blocked_gets:
                                coro.send(self._conn)
                            break
                else:
                    # just ignore a Broken notification for anything but the current connection,
                    # the sender will just retry and get the current connection
                    pass
            else:
                assert isinstance(req, New)
                self._conn = req.conn
                coro.send(None)

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        while True:
            conn = await self.conn_queue.request(Get())
            assert conn is not None
            try:
                return await conn.syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
            except SyscallSendError as exc:
                await self.conn_queue.request(Broken(conn))

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def clone_persistent(
        parent: Process, path: t.Union[str, os.PathLike],
) -> PersistentProcess:
    """Create a new not-yet-persistent process and return the process and its tracking object

    To make the process actually persistent, you must call PersistentServer.make_persistent().

    The point of this hoop-jumping is just to prevent unnecessary resource leakage, so you
    can set up things in a persistent process and only make it persistent when you're
    actually ready.

    A persistent process is essentially the same as a normal process, just running a
    different function. As such, it starts off sharing its file descriptor table and
    everything else with its parent process. It's only when we disconnect and reconnect
    that it changes behavior.

    """
    listening_sock = await parent.task.socket(AF.UNIX, SOCK.STREAM)
    await listening_sock.bind(await parent.ram.ptr(await SockaddrUn.from_path(parent, path)))
    await listening_sock.listen(1)
    child_pid, task = await clone_child_task(
        parent.task, parent.ram, parent.connection, parent.loader, parent.monitor,
        CLONE.FILES|CLONE.FS|CLONE.SIGHAND,
        lambda sock: Trampoline(parent.loader.persistent_server_func, [sock, sock, listening_sock]))
    listening_sock_handle = listening_sock.move(task)
    ram = RAM(task, parent.ram.transport, parent.ram.allocator.inherit(task))

    ## create the new persistent task
    epoller = await Epoller.make_root(ram, task)
    signal_block = SignalBlock(task, await ram.ptr(Sigset({SIG.CHLD})))
    # TODO use an inherited signalfd instead
    child_monitor = await ChildPidMonitor.make(ram, task, epoller, signal_block=signal_block)
    return PersistentProcess(Process(
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

async def _connect_and_send(
        self: PersistentProcess, process: Process,
        syscall_sock: FileDescriptor, data_sock: FileDescriptor,
) -> t.Tuple[FileDescriptor, FileDescriptor]:
    """Connect to a persistent process's socket, send some file descriptors

    """
    fds = [syscall_sock, data_sock]
    sock = await process.make_afd(await process.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
    sockaddr_un = await SockaddrUn.from_path(process, self.persistent_path)
    async def sendmsg_op(sem: RAM) -> t.Tuple[
            WrittenPointer[SockaddrUn], WrittenPointer[Int32], WrittenPointer[SendMsghdr], Pointer[StructList[Int32]]]:
        addr = await sem.ptr(sockaddr_un)
        count = await sem.ptr(Int32(len(fds)))
        iovec = await sem.ptr(IovecList([await sem.malloc(bytes, 1)]))
        cmsgs = await sem.ptr(CmsgList([CmsgSCMRights(fds)]))
        hdr = await sem.ptr(SendMsghdr(None, iovec, cmsgs))
        response_buf = await sem.ptr(StructList(Int32, [Int32(0)]*len(fds)))
        return addr, count, hdr, response_buf
    addr, count, hdr, response = await process.ram.perform_batch(sendmsg_op)
    data = None
    await sock.connect(addr)
    _, _ = await sock.write(count)
    _, [] = await sock.handle.sendmsg(hdr, SendmsgFlags.NONE)
    while response.size() > 0:
        valid, response = await sock.read(response)
        data += valid
    remote_syscall_sock, remote_data_sock = [self.task.make_fd_handle(near.FileDescriptor(int(i)))
                  for i in ((await data.read()).elems if data else [])]
    await sock.close()
    return remote_syscall_sock, remote_data_sock

class PersistentProcess(Process):
    """A process which can live on even if everything else has exited

    It's not persistent by default - you need to call make_persistent() first to make that
    happen. After that, this process will continue living even if its parent dies or our
    connection to it fails, and you can reconnect to it by calling reconnect(thr), passing
    the process you want to initiate the connection from.

    A great name for this would be "daemon process", but that's already taken by more
    conventional process systems to refer to a much more conventional kind of process.  I
    wistfully recall the name I gave to a previous attempt at making a hosting system for
    long-running tasks: daemon engines. That was a great name.

    """
    def __init__(self,
                 process: Process,
                 persistent_path: t.Union[str, os.PathLike],
                 persistent_sock: FileDescriptor,
    ) -> None:
        super()._init_from(process)
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
        "Make this process actually persistent"
        await self.prep_for_reconnect()
        await self.task.setsid()
        await self.task.prctl(PR.SET_PDEATHSIG, 0)

    async def reconnect(self, process: Process) -> None:
        """Using the passed-in process to establish the connection, reconnect to this PersistentProcess

        """
        if not self.prepped_for_reconnect:
            # It does work to reconnect without prep_for_reconnect, except for one nitpick:
            # If the underlying process for the PersistentProcess dies while we're in the
            # middle of reconnecting to it, the file descriptors opened by the C code
            # running in the process will leak if the process is in a shared fd table.
            # That's annoying on its own, but also means we won't get an EOF from our
            # communication with the process, and we'll just hang forever.
            await self.prep_for_reconnect()
        await self.task.run_fd_table_gc(use_self=False)
        if not isinstance(self.task.sysif, PersistentSyscallConnection):
            raise Exception("self.task.sysif of unexpected type", self.task.sysif)
        await self.task.sysif.shutdown_current_connection()
        [(access_syscall_sock, syscall_sock), (access_data_sock, data_sock)] = await process.open_async_channels(2)
        serverfd, remote_data_sock = await _connect_and_send(self, process, syscall_sock, data_sock)
        await syscall_sock.close()
        await data_sock.close()
        # Set up the new SyscallConnection
        conn = SyscallConnection(
            self.task.sysif.logger,
            access_syscall_sock,
            serverfd,
        )
        await self.task.sysif.set_new_conn(conn)
        # Fix up RAM with new transport
        # TODO technically this could still be in the same address space - that's the case in our tests.
        # we should figure out a way to use a LocalMemoryTransport here so it can copy efficiently
        transport = SocketMemoryTransport(access_data_sock, remote_data_sock)
        self.ram.transport = transport
        self.transport = transport
        # close remote fds we don't have handles to; this includes the old interface fds.
        await self.task.run_fd_table_gc()
