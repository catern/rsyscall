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
                 access_connection: t.Optional[t.Tuple[WrittenPointer[Address], FileDescriptor]],
                 connecting_ram: RAM,
                 # TODO we need to lock this, and the access_connection also.
                 # they are shared between processes...
                 connecting_connection: t.Tuple[FileDescriptor, FileDescriptor],
    ) -> None:
        self._access_task = access_task
        self._access_ram = access_ram
        self._access_epoller = access_epoller
        self._access_connection = access_connection
        self._connecting_ram = connecting_ram
        self._connecting_connection = connecting_connection

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]: ...

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]: ...

from rsyscall.sys.socket import AF, SOCK, SendmsgFlags, RecvmsgFlags
from rsyscall.struct import Bytes
import rsyscall.handle as handle
import rsyscall.batch as batch
async def make_connections(access_task: Task,
                           access_ram: RAM,
                           # regrettably asymmetric...
                           # it would be nice to unify connect/accept with passing file descriptors somehow.
                           access_connection: t.Optional[t.Tuple[t.Any, handle.FileDescriptor]],
                           connecting_task: Task,
                           connecting_ram: RAM,
                           connecting_connection: t.Tuple[handle.FileDescriptor, handle.FileDescriptor],
                           parent_task: Task,
                           parent_ram: RAM,
                           count: int) -> t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]]:
    # so there's 1. the access task, through which we access the syscall and data fds,
    # 2. the parent task, and
    # 3. the connection between the access and parent task, so that we can have the parent task pass down the fds,
    # while the access task uses them.
    # okay but this is a slight simplification, because there may also be,
    # 4. the connection task, which is a task that actually gets the fds and passes them down to the parent task
    access_socks: t.List[handle.FileDescriptor] = []
    connecting_socks: t.List[handle.FileDescriptor] = []
    if access_task.fd_table == connecting_task.fd_table:
        async def make_conn() -> t.Tuple[handle.FileDescriptor, handle.FileDescriptor]:
            pair = await (await access_task.socketpair(
                AF.UNIX, SOCK.STREAM, 0, await access_ram.malloc_struct(handle.FDPair))).read()
            return (pair.first, pair.second)
    else:
        if access_connection is not None:
            access_connection_path, access_connection_socket = access_connection
        else:
            raise Exception("must pass access connection when access task and connecting task are different")
        async def make_conn() -> t.Tuple[handle.FileDescriptor, handle.FileDescriptor]:
            addr = await access_connection_path.as_sockaddr_un()
            addrptr = await access_ram.to_pointer(addr)
            left_sock = await access_task.socket(addrptr.value.family, SOCK.STREAM)
            await left_sock.connect(addrptr)
            await addr.close()
            right_sock = await access_connection_socket.accept(SOCK.CLOEXEC)
            return left_sock, right_sock
    for _ in range(count):
        access_sock, connecting_sock = await make_conn()
        access_socks.append(access_sock)
        connecting_socks.append(connecting_sock)
    passed_socks: t.List[handle.FileDescriptor]
    if connecting_task.fd_table == parent_task.fd_table:
        passed_socks = []
        for sock in connecting_socks:
            passed_socks.append(sock.move(parent_task))
    else:
        assert connecting_connection is not None
        def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.SendMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([sock for sock in connecting_socks])]))
            return sem.to_pointer(handle.SendMsghdr(None, iovec, cmsgs))
        _, [] = await connecting_connection[0].sendmsg(await connecting_ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
        def recvmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.RecvMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([sock for sock in connecting_socks])]))
            return sem.to_pointer(handle.RecvMsghdr(None, iovec, cmsgs))
        _, [], hdr = await connecting_connection[1].recvmsg(await parent_ram.perform_batch(recvmsg_op), RecvmsgFlags.NONE)
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
