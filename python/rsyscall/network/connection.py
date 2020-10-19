"""Functions and classes for a connection between two threads, with which we can open channels for data transfer
"""
from __future__ import annotations
from dneio import make_n_in_parallel
import abc
import typing as t
import trio
from rsyscall.epoller import AsyncFileDescriptor, Epoller
from rsyscall.handle import FileDescriptor, WrittenPointer, Task
from rsyscall.memory.ram import RAM

from rsyscall.sys.socket import AF, SOCK, Sockaddr, SendmsgFlags, RecvmsgFlags, SendMsghdr, RecvMsghdr, CmsgList, CmsgSCMRights, Socketpair
from rsyscall.sys.uio import IovecList
from rsyscall.fcntl import F, O

class Connection:
    """A connection between two threads through which more bidirectional channels can be opened

    You could think of this as a pre-established route between two threads; or a cable
    between them; these are connections which can be multiplexed over to create multiple
    bidirectional channels for data transfer.

    This is not necessarily a connection in the style of TCP as such; it merely represents
    that there is a way to open channels between two threads, not that there is any active
    transfer between them at the moment. TCP doesn't support opening new channels, so
    merely having an open TCP connection isn't enough to implement this interface. On the
    other hand, SCTP and QUIC do support opening new channels, so a SCTP or QUIC
    connection would be enough to implement this interface.

    """
    @abc.abstractmethod
    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        "Batched version of open_channel"
        pass

    async def open_channel(self) -> t.Tuple[FileDescriptor, FileDescriptor]:
        """Open a bidirectional channel between the two threads inside this connection

        The left side of a channel is the "local" side, and the right side is the "remote"
        side. Accesses to the local side are typically more efficient than accesses to the
        right side. Typically, in fact, the left side of the channel is in the local
        thread, although this is not required to be true.

        """
        [pair] = await self.open_channels(1)
        return pair

    @abc.abstractmethod
    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]:
        "Batched version of open_async_channel"
        pass

    async def open_async_channel(self) -> t.Tuple[AsyncFileDescriptor, FileDescriptor]:
        """Like open_channel, but returns the left side as an AsyncFileDescriptor

        As discussed in open_channel's docstring, the left side is the "local" side, and
        is more efficient to access. Here we take that further: Since an AFD comes with a
        RAM, we can immediately read and write Python bytes to the left side of this
        channel. This provides an efficient way to transfer data between Python and things
        which operate on file descriptors, such as subprocesses.

        This is how we establish all our syscall or data connections for new threads;
        open_async_channel returns the most direct path possible, so we know that when
        we're sending syscalls to a thread, that data is being efficiently transferred; in
        most cases, directly between the local thread and the syscall server.

        """
        [pair] = await self.open_async_channels(1)
        return pair


    @abc.abstractmethod
    async def prep_fd_transfer(self) -> t.Tuple[FileDescriptor, t.Callable[[Task, RAM, FileDescriptor], Connection]]:
        """Prepare to transfer this Connection to another task; call the callable to execute

        The user should use whatever means to transport the returned file descriptor to
        the other task, then call the callable with the appropriate other task, a RAM for
        it, and the transferred file descriptor.

        The user might do this through fd inheritance, or maybe passing the fd over a Unix
        socket with SCM_RIGHTS.

        This is an async method because the connection might need to allocate some
        resources to do this.

        """
        pass

    @abc.abstractmethod
    def inherit(self, task: Task, ram: RAM) -> Connection:
        """Transfer this Connection to a new task by using "inherit" to move the fds"""
        pass

class FDPassConnection(Connection):
    """A socketpair between two threads over which we can pass fds to establish new channels

    If the two threads are in the same fd table, then we'll skip using SCM_RIGHTS to pass
    the new socketpairs around and instead just change the fd owner.

    See Connnection for more details on this interface.

    """
    @staticmethod
    async def make(task: Task, ram: RAM, epoller: Epoller) -> FDPassConnection:
        pair = await (await task.socketpair(AF.UNIX, SOCK.STREAM, 0, await ram.malloc(Socketpair))).read()
        return FDPassConnection(task, ram, epoller, pair.first, task, ram, pair.second)

    def __init__(self, access_task: Task, access_ram: RAM, access_epoller: Epoller, access_fd: FileDescriptor,
                 task: Task, ram: RAM, fd: FileDescriptor) -> None:
        self.access_task = access_task
        self.access_ram = access_ram
        self.access_epoller = access_epoller
        self.access_fd = access_fd
        self.task = task
        self.ram = ram
        self.fd = fd

    async def move_fds(self, fds: t.List[FileDescriptor]) -> t.List[FileDescriptor]:
        "Move the passed-in file descriptors from self.access_task to self.task"
        if self.access_task.fd_table == self.task.fd_table:
            return [fd.move(self.task) for fd in fds]
        async def sendmsg_op(sem: RAM) -> WrittenPointer[SendMsghdr]:
            iovec = await sem.ptr(IovecList([await sem.malloc(bytes, 1)]))
            cmsgs = await sem.ptr(CmsgList([CmsgSCMRights([fd for fd in fds])]))
            return await sem.ptr(SendMsghdr(None, iovec, cmsgs))
        _, [] = await self.access_fd.sendmsg(await self.access_ram.perform_batch(sendmsg_op))
        async def recvmsg_op(sem: RAM) -> WrittenPointer[RecvMsghdr]:
            iovec = await sem.ptr(IovecList([await sem.malloc(bytes, 1)]))
            cmsgs = await sem.ptr(CmsgList([CmsgSCMRights([fd for fd in fds])]))
            return await sem.ptr(RecvMsghdr(None, iovec, cmsgs))
        _, [], hdr = await self.fd.recvmsg(await self.ram.perform_batch(recvmsg_op))
        cmsgs_ptr = (await hdr.read()).control
        if cmsgs_ptr is None:
            raise Exception("cmsgs field of header is, impossibly, None")
        [cmsg] = await cmsgs_ptr.read()
        if not isinstance(cmsg, CmsgSCMRights):
            raise Exception("expected SCM_RIGHTS cmsg, instead got", cmsg)
        passed_socks = cmsg
        for sock in fds:
            await sock.close()
        return passed_socks

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        async def make() -> Socketpair:
            return await (await self.access_task.socketpair(
                AF.UNIX, SOCK.STREAM, 0, await self.access_ram.malloc(Socketpair))).read()
        pairs = await make_n_in_parallel(make, count)
        fds = await self.move_fds([pair.second for pair in pairs])
        return [(pair.first, fd) for pair, fd in zip(pairs, fds)]

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]:
        chans = await self.open_channels(count)
        access_socks, local_socks = zip(*chans)
        async def make_afd(sock: FileDescriptor) -> AsyncFileDescriptor:
            # have to set NONBLOCK after creation because we want the other end to be blocking
            await sock.fcntl(F.SETFL, O.NONBLOCK)
            return await AsyncFileDescriptor.make(self.access_epoller, self.access_ram, sock)
        async_access_socks = [await make_afd(sock) for sock in access_socks]
        return list(zip(async_access_socks, local_socks))

    async def prep_fd_transfer(self) -> t.Tuple[FileDescriptor, t.Callable[[Task, RAM, FileDescriptor], FDPassConnection]]:
        return self.fd, self.for_task_with_fd

    def for_task_with_fd(self, task: Task, ram: RAM, fd: FileDescriptor) -> FDPassConnection:
        return FDPassConnection(
            self.access_task,
            self.access_ram,
            self.access_epoller,
            self.access_fd,
            task, ram, fd)

    def inherit(self, task: Task, ram: RAM) -> FDPassConnection:
        return self.for_task_with_fd(task, ram, self.fd.inherit(task))

class ListeningConnection(Connection):
    """An (address, listening socket) pair with which we can do connect(); accept(); to establish a new channel.
    
    See Connnection for more details on this interface.

    """
    def __init__(self,
                 access_task: Task,
                 access_ram: RAM,
                 access_epoller: Epoller,
                 access_address: WrittenPointer[Sockaddr],
                 task: Task,
                 ram: RAM,
                 listening_fd: AsyncFileDescriptor,
    ) -> None:
        self.access_task = access_task
        self.access_ram = access_ram
        self.access_epoller = access_epoller
        self.access_address = access_address
        self.task = task
        self.ram = ram
        self.listening_fd = listening_fd

    async def open_async_channel(self) -> t.Tuple[AsyncFileDescriptor, FileDescriptor]:
        access_sock = await AsyncFileDescriptor.make(
            self.access_epoller, self.access_ram,
            await self.access_task.socket(self.access_address.value.family, SOCK.STREAM|SOCK.NONBLOCK))
        await access_sock.connect(self.access_address)
        sock = await self.listening_fd.accept()
        return access_sock, sock

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]:
        return [await self.open_async_channel() for _ in range(count)]

    async def open_channel(self) -> t.Tuple[FileDescriptor, FileDescriptor]:
        access_sock = await self.access_task.socket(self.access_address.value.family, SOCK.STREAM)
        # TODO this connect should really be async
        # but, since we're just connecting to a unix socket, it's fine I guess.
        await access_sock.connect(self.access_address)
        sock = await self.listening_fd.accept()
        return access_sock, sock

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        return [await self.open_channel() for _ in range(count)]

    async def prep_fd_transfer(self) -> t.Tuple[FileDescriptor, t.Callable[[Task, RAM, FileDescriptor], Connection]]:
        return self.listening_fd.handle, self.for_task_with_fd

    def for_task_with_fd(self, task: Task, ram: RAM, fd: FileDescriptor) -> ListeningConnection:
        return ListeningConnection(
            self.access_task,
            self.access_ram,
            self.access_epoller,
            self.access_address,
            task, ram, self.listening_fd.with_handle(fd),
        )

    def inherit(self, task: Task, ram: RAM) -> ListeningConnection:
        return self.for_task_with_fd(task, ram, self.listening_fd.handle.inherit(task))
