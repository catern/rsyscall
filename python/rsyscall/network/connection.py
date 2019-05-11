from __future__ import annotations
import abc
import typing as t
import trio
from rsyscall.epoller import AsyncFileDescriptor, EpollCenter
from rsyscall.handle import FileDescriptor, WrittenPointer, Task
from rsyscall.memory.ram import RAM
from rsyscall.struct import Bytes
from rsyscall.batch import BatchSemantics

from rsyscall.sys.socket import AF, SOCK, Address, SendmsgFlags, RecvmsgFlags, SendMsghdr, RecvMsghdr, CmsgList, CmsgSCMRights
from rsyscall.sys.uio import IovecList
from rsyscall.handle import FDPair

T = t.TypeVar('T')
async def make_n_in_parallel(make: t.Callable[[], t.Awaitable[T]], count: int) -> t.List[T]:
    pairs: t.List[t.Any] = [None]*count
    async with trio.open_nursery() as nursery:
        async def open_nth(n: int) -> None:
            pairs[n] = await make()
        for i in range(count):
            nursery.start_soon(open_nth, i)
    return pairs

class ConnectionInterface:
    @abc.abstractmethod
    async def open_channel(self) -> t.Tuple[FileDescriptor, FileDescriptor]: ...

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        return await make_n_in_parallel(self.open_channel, count)

class ListeningConnection(ConnectionInterface):
    def __init__(self,
                 address_task: Task,
                 address: WrittenPointer[Address],
                 listener_fd: FileDescriptor,
    ) -> None:
        self.address_task = address_task
        self.address = address
        self.listener_fd = listener_fd

    async def open_channel(self) -> t.Tuple[FileDescriptor, FileDescriptor]:
        address_sock = await self.address_task.socket(self.address.value.family, SOCK.STREAM)
        # TODO this connect should really be async
        # but, since we're just connecting to a unix socket, it's fine I guess.
        await address_sock.connect(self.address)
        # TODO this accept should really be async
        listener_sock = await self.listener_fd.accept(SOCK.CLOEXEC)
        return address_sock, listener_sock

class SocketpairConnection(ConnectionInterface):
    def __init__(self, task: Task, ram: RAM, dest_task: Task) -> None:
        if task.fd_table != dest_task.fd_table:
            raise Exception("task and dest_task are in separate fd tables; "
                            "we can't use a SocketpairConnection between them.")
        self.task = task
        self.ram = ram
        self.dest_task = dest_task

    async def open_channel(self) -> t.Tuple[FileDescriptor, FileDescriptor]:
        pair = await (await self.task.socketpair(
            AF.UNIX, SOCK.STREAM, 0, await self.ram.malloc_struct(FDPair))).read()
        return (pair.first, pair.second.move(self.dest_task))

class MoverInterface:
    @abc.abstractmethod
    async def move_fds(self, fds: t.List[FileDescriptor]) -> t.List[FileDescriptor]: ...

class SameFDTableMover(MoverInterface):
    def __init__(self, task: Task) -> None:
        self.task = task

    async def move_fds(self, fds: t.List[FileDescriptor]) -> t.List[FileDescriptor]:
        return [fd.move(self.task) for fd in fds]

class SCMRightsMover(MoverInterface):
    def __init__(self,
                 from_ram: RAM, from_fd: FileDescriptor,
                 to_ram: RAM, to_fd: FileDescriptor,
    ) -> None:
        self.from_ram = from_ram
        self.from_fd = from_fd
        self.to_ram = to_ram
        self.to_fd = to_fd

    async def move_fds(self, fds: t.List[FileDescriptor]) -> t.List[FileDescriptor]:
        def sendmsg_op(sem: BatchSemantics) -> WrittenPointer[SendMsghdr]:
            iovec = sem.to_pointer(IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(CmsgList([CmsgSCMRights([fd for fd in fds])]))
            return sem.to_pointer(SendMsghdr(None, iovec, cmsgs))
        _, [] = await self.from_fd.sendmsg(await self.from_ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
        def recvmsg_op(sem: BatchSemantics) -> WrittenPointer[RecvMsghdr]:
            iovec = sem.to_pointer(IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(CmsgList([CmsgSCMRights([fd for fd in fds])]))
            return sem.to_pointer(RecvMsghdr(None, iovec, cmsgs))
        _, [], hdr = await self.to_fd.recvmsg(await self.to_ram.perform_batch(recvmsg_op), RecvmsgFlags.NONE)
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

    def for_task_with_fd(self, ram: RAM, fd: FileDescriptor) -> SCMRightsMover:
        return SCMRightsMover(self.from_ram, self.from_fd, ram, fd)

class Connection:
    @abc.abstractmethod
    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]: ...
    @abc.abstractmethod
    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]: ...
    @abc.abstractmethod
    async def prep_for_unshare_files(self) -> None: ...
    @abc.abstractmethod
    async def prep_fd_transfer(self) -> t.Tuple[FileDescriptor, t.Callable[[Task, RAM, FileDescriptor], Connection]]: ...
    @abc.abstractmethod
    def for_task(self, task: Task, ram: RAM) -> Connection: ...

class LocalConnection(Connection):
    @staticmethod
    async def make(task: Task, ram: RAM, epoller: EpollCenter) -> LocalConnection:
        pair = await (await task.socketpair(AF.UNIX, SOCK.STREAM, 0, await ram.malloc_struct(FDPair))).read()
        return LocalConnection(task, ram, epoller, task, ram, SCMRightsMover(ram, pair.first, ram, pair.second))

    def __init__(self, access_task: Task, access_ram: RAM, access_epoller: EpollCenter,
                 task: Task, ram: RAM,
                 scm_mover: SCMRightsMover) -> None:
        self.access_task = access_task
        self.access_ram = access_ram
        self.access_epoller = access_epoller
        self.task = task
        self.ram = ram
        self.scm_mover = scm_mover

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]:
        chans = await self.open_channels(count)
        access_socks, local_socks = zip(*chans)
        async_access_socks = [await AsyncFileDescriptor.make_handle(self.access_epoller, self.access_ram, sock)
                              for sock in access_socks]
        return list(zip(async_access_socks, local_socks))

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        async def make() -> FDPair:
            return await (await self.access_task.socketpair(
                AF.UNIX, SOCK.STREAM, 0, await self.access_ram.malloc_struct(FDPair))).read()
        pairs = await make_n_in_parallel(make, count)
        if self.access_task.fd_table == self.task.fd_table:
            mover: MoverInterface = SameFDTableMover(self.task)
        else:
            mover = self.scm_mover
        fds = await mover.move_fds([pair.second for pair in pairs])
        return [(pair.first, fd) for pair, fd in zip(pairs, fds)]

    async def prep_for_unshare_files(self) -> None:
        pass

    async def prep_fd_transfer(self) -> t.Tuple[FileDescriptor, t.Callable[[Task, RAM, FileDescriptor], LocalConnection]]:
        def f(task: Task, ram: RAM, fd: FileDescriptor) -> LocalConnection:
            return self.for_task_with_fd(task, ram, fd)
        return self.scm_mover.to_fd, f

    def for_task_with_fd(self, task: Task, ram: RAM, fd: FileDescriptor) -> LocalConnection:
        return LocalConnection(
            self.access_task,
            self.access_ram,
            self.access_epoller,
            task, ram, self.scm_mover.for_task_with_fd(ram, fd))

    def for_task(self, task: Task, ram: RAM) -> LocalConnection:
        return self.for_task_with_fd(task, ram, self.scm_mover.to_fd.for_task(task))

class FullConnection(Connection):
    def __init__(self,
                 access_task: Task,
                 access_ram: RAM,
                 access_epoller: EpollCenter,
                 # regrettably asymmetric...
                 # it would be nice to unify connect/accept with passing file descriptors somehow.
                 access_connection: t.Tuple[WrittenPointer[Address], FileDescriptor],
                 connecting_task: Task,
                 connecting_ram: RAM,
                 # TODO we need to lock this, and the access_connection also.
                 # they are shared between processes...
                 connecting_connection: t.Tuple[FileDescriptor, FileDescriptor],
                 task: Task,
                 ram: RAM,
    ) -> None:
        if access_connection:
            address, listening_fd = access_connection
            self.first_conn: ConnectionInterface = ListeningConnection(access_task, address, listening_fd)
        else:
            raise Exception
        self.access_task = access_task
        self.access_ram = access_ram
        self.access_epoller = access_epoller
        self.access_connection = access_connection
        self.connecting_task = connecting_task
        self.connecting_ram = connecting_ram
        self.connecting_connection = connecting_connection
        self.task = task
        self.ram = ram
        if self.connecting_task.fd_table == self.task.fd_table:
            self.mover: MoverInterface = SameFDTableMover(self.task)
        else:
            from_fd, to_fd = self.connecting_connection
            self.mover = SCMRightsMover(self.connecting_ram, from_fd, self.ram, to_fd)

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]:
        chans = await self.open_channels(count)
        access_socks, local_socks = zip(*chans)
        async_access_socks = [await AsyncFileDescriptor.make_handle(self.access_epoller, self.access_ram, sock)
                              for sock in access_socks]
        return list(zip(async_access_socks, local_socks))

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        return await make_connections(self, count)

    async def prep_for_unshare_files(self) -> None:
        if isinstance(self.mover, SameFDTableMover):
            # make fd pair, and stick it into the connecting task and task.
            pair = await (await self.task.socketpair(AF.UNIX, SOCK.STREAM, 0, await self.ram.malloc_struct(FDPair))).read()
            self.mover = SCMRightsMover(self.connecting_ram, pair.first.move(self.connecting_task), self.ram, pair.second)

    async def prep_fd_transfer(self) -> t.Tuple[FileDescriptor, t.Callable[[Task, RAM, FileDescriptor], Connection]]:
        def f(task: Task, ram: RAM, fd: FileDescriptor) -> FullConnection:
            return self.for_task_with_fd(task, ram, fd)
        return self.connecting_connection[1], f

    def for_task_with_fd(self, task: Task, ram: RAM, fd: FileDescriptor) -> FullConnection:
        return FullConnection(
            self.access_task,
            self.access_ram,
            self.access_epoller,
            self.access_connection,
            self.connecting_task, self.connecting_ram,
            (self.connecting_connection[0], fd),
            task, ram,
        )

    def for_task(self, task: Task, ram: RAM) -> FullConnection:
        return self.for_task_with_fd(task, ram, self.connecting_connection[1].for_task(task))

async def make_connections(self: FullConnection, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
    # so there's 1. the access task, through which we access the syscall and data fds,
    # 2. the parent task, and
    # 3. the connection between the access and parent task, so that we can have the parent task pass down the fds,
    # while the access task uses them.
    # okay but this is a slight simplification, because there may also be,
    # 4. the connection task, which is a task that actually gets the fds and passes them down to the parent task
    connecting_socks: t.List[FileDescriptor]
    pairs = await self.first_conn.open_channels(count)
    lastfds = await self.mover.move_fds([midfd for _, midfd in pairs])
    return [(firstfd, lastfd) for (firstfd, _), lastfd in zip(pairs, lastfds)]
