import abc
import typing as t
from rsyscall.epoller import AsyncFileDescriptor, EpollCenter
from rsyscall.handle import FileDescriptor, WrittenPointer, Task
from rsyscall.memory.ram import RAM
from rsyscall.sys.socket import Address

class Connection:
    def __init__(self,
                 access_task: Task,
                 access_ram: RAM,
                 access_epoller: EpollCenter,
                 # regrettably asymmetric...
                 # it would be nice to unify connect/accept with passing file descriptors somehow.
                 access_connection: t.Optional[t.Tuple[WrittenPointer[Address], FileDescriptor]],
                 connecting_task: Task,
                 connecting_ram: RAM,
                 # TODO we need to lock this, and the access_connection also.
                 # they are shared between processes...
                 connecting_connection: t.Tuple[FileDescriptor, FileDescriptor],
                 task: Task,
                 ram: RAM,
    ) -> None:
        self.access_task = access_task
        self.access_ram = access_ram
        self.access_epoller = access_epoller
        self.access_connection = access_connection
        self.connecting_task = connecting_task
        self.connecting_ram = connecting_ram
        self.connecting_connection = connecting_connection
        self.task = task
        self.ram = ram

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]:
        chans = await self.open_channels(count)
        access_socks, local_socks = zip(*chans)
        async_access_socks = [await AsyncFileDescriptor.make_handle(self.access_epoller, self.access_ram, sock)
                              for sock in access_socks]
        return list(zip(async_access_socks, local_socks))

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        return await make_connections(self, count)

from rsyscall.sys.socket import AF, SOCK, SendmsgFlags, RecvmsgFlags
from rsyscall.struct import Bytes
import rsyscall.handle as handle
import rsyscall.batch as batch
async def make_connections(self: Connection, count: int) -> t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]]:
    # so there's 1. the access task, through which we access the syscall and data fds,
    # 2. the parent task, and
    # 3. the connection between the access and parent task, so that we can have the parent task pass down the fds,
    # while the access task uses them.
    # okay but this is a slight simplification, because there may also be,
    # 4. the connection task, which is a task that actually gets the fds and passes them down to the parent task
    access_socks: t.List[handle.FileDescriptor] = []
    connecting_socks: t.List[handle.FileDescriptor] = []
    if self.access_task.fd_table == self.connecting_task.fd_table:
        async def make_conn() -> t.Tuple[handle.FileDescriptor, handle.FileDescriptor]:
            pair = await (await self.access_task.socketpair(
                AF.UNIX, SOCK.STREAM, 0, await self.access_ram.malloc_struct(handle.FDPair))).read()
            return (pair.first, pair.second)
    else:
        if self.access_connection is not None:
            access_connection_addr, access_connection_socket = self.access_connection
        else:
            raise Exception("must pass access connection when access task and connecting task are different")
        async def make_conn() -> t.Tuple[handle.FileDescriptor, handle.FileDescriptor]:
            left_sock = await self.access_task.socket(access_connection_addr.value.family, SOCK.STREAM)
            # TODO this connect should really be async
            # but, since we're just connecting to a unix socket, it's fine I guess.
            await left_sock.connect(access_connection_addr)
            # TODO this accept should really be async
            right_sock = await access_connection_socket.accept(SOCK.CLOEXEC)
            return left_sock, right_sock
    for _ in range(count):
        access_sock, connecting_sock = await make_conn()
        access_socks.append(access_sock)
        connecting_socks.append(connecting_sock)
    passed_socks: t.List[handle.FileDescriptor]
    if self.connecting_task.fd_table == self.task.fd_table:
        passed_socks = []
        for sock in connecting_socks:
            passed_socks.append(sock.move(self.task))
    else:
        assert self.connecting_connection is not None
        def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.SendMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([sock for sock in connecting_socks])]))
            return sem.to_pointer(handle.SendMsghdr(None, iovec, cmsgs))
        _, [] = await self.connecting_connection[0].sendmsg(await self.connecting_ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
        def recvmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.RecvMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([sock for sock in connecting_socks])]))
            return sem.to_pointer(handle.RecvMsghdr(None, iovec, cmsgs))
        _, [], hdr = await self.connecting_connection[1].recvmsg(await self.ram.perform_batch(recvmsg_op), RecvmsgFlags.NONE)
        cmsgs_ptr = (await hdr.read()).control
        if cmsgs_ptr is None:
            raise Exception("cmsgs field of header is, impossibly, None")
        [cmsg] = await cmsgs_ptr.read()
        if not isinstance(cmsg, handle.CmsgSCMRights):
            raise Exception("expected SCM_RIGHTS cmsg, instead got", cmsg)
        passed_socks = cmsg
        # don't need these in the connecting task anymore
        for sock in connecting_socks:
            await sock.close()
    ret = list(zip(access_socks, passed_socks))
    return ret
