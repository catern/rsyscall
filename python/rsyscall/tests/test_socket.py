from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread

from rsyscall.sys.socket import *
from rsyscall.sys.un import *
from rsyscall.sys.uio import IovecList
from rsyscall.fcntl import O
from rsyscall.linux.dirent import DirentList
from rsyscall.stdlib import mkdtemp

import logging
logger = logging.getLogger(__name__)

class TestSocket(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread
        self.tmpdir = await mkdtemp(self.thr)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_listen(self) -> None:
        sockfd = await self.thr.task.socket(AF.UNIX, SOCK.STREAM)
        addr = await self.thr.ram.ptr(await SockaddrUn.from_path(self.thr, self.tmpdir/"sock"))
        await sockfd.bind(addr)
        await sockfd.listen(10)

        clientfd = await self.thr.task.socket(AF.UNIX, SOCK.STREAM)
        await clientfd.connect(addr)
        connfd = await sockfd.accept()

    async def test_listen_async(self) -> None:
        sockfd = await self.thr.make_afd(await self.thr.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        addr = await self.thr.ram.ptr(await SockaddrUn.from_path(self.thr, self.tmpdir/"sock"))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)

        clientfd = await self.thr.make_afd(await self.thr.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        await clientfd.connect(addr)
        connfd, client_addr = await sockfd.accept_addr()
        logger.info("%s, %s", addr, client_addr)
        await connfd.close()
        await sockfd.close()
        await clientfd.close()

    async def test_listen_async_accept(self) -> None:
        sockfd = await self.thr.make_afd(await self.thr.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        addr = await self.thr.ram.ptr(await SockaddrUn.from_path(self.thr, self.tmpdir/"sock"))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)

        clientfd = await self.thr.make_afd(await self.thr.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        await clientfd.connect(addr)

        connfd_h, client_addr = await sockfd.accept_addr(SOCK.NONBLOCK)
        connfd = await self.thr.make_afd(connfd_h)
        logger.info("%s, %s", addr, client_addr)
        data = b"hello"
        await connfd.write_all_bytes(data)
        self.assertEqual(data, await clientfd.read_some_bytes())
        await connfd.close()
        await sockfd.close()
        await clientfd.close()

    async def test_pass_fd(self) -> None:
        fds = await (await self.thr.task.socketpair(
            AF.UNIX, SOCK.STREAM, 0,
            await self.thr.ram.malloc(Socketpair))).read()
        in_data = b"hello"

        iovec = await self.thr.ram.ptr(IovecList([await self.thr.ram.ptr(in_data)]))
        cmsgs = await self.thr.ram.ptr(CmsgList([CmsgSCMRights([fds.second])]))
        [written], [] = await fds.second.sendmsg(
            await self.thr.ram.ptr(SendMsghdr(None, iovec, cmsgs)), SendmsgFlags.NONE)

        [valid], [], hdr = await fds.first.recvmsg(
            await self.thr.ram.ptr(RecvMsghdr(None, iovec, cmsgs)), RecvmsgFlags.NONE)

        self.assertEqual(in_data, await valid.read())

        hdrval = await hdr.read()
        [[passed_fd]] = await hdrval.control.read() # type: ignore
        self.assertEqual(hdrval.name, None)
        self.assertEqual(hdrval.flags, MsghdrFlags.CMSG_CLOEXEC)


    async def test_shutdown_read(self) -> None:
        "When we shutdown(SHUT.RD) a socket and read from it, we get pending data then EOF"
        fds = await (await self.thr.task.socketpair(
            AF.UNIX, SOCK.STREAM, 0,
            await self.thr.ram.malloc(Socketpair))).read()

        data = b'hello'
        await fds.second.write(await self.thr.ptr(data))
        await fds.first.shutdown(SHUT.RD)
        read, _ = await fds.first.read(await self.thr.malloc(bytes, 4096))
        self.assertEqual(read.size(), len(data))

    async def test_long_sockaddr(self) -> None:
        "SockaddrUn.from_path works correctly on long Unix socket paths"
        longdir = await self.thr.ram.ptr(self.tmpdir/("long"*50))
        await self.thr.task.mkdir(longdir)
        addr = await self.thr.ram.ptr(await SockaddrUn.from_path(self.thr, longdir.value/"sock"))

        sockfd = await self.thr.task.socket(AF.UNIX, SOCK.STREAM)
        await sockfd.bind(addr)
        await sockfd.listen(10)
        
        clientfd = await self.thr.task.socket(AF.UNIX, SOCK.STREAM)
        await clientfd.connect(addr)
        connfd = await sockfd.accept()

        dirfd = await self.thr.task.open(longdir, O.DIRECTORY)
        valid, rest = await dirfd.getdents(await self.thr.ram.malloc(DirentList, 4096))
        self.assertCountEqual([dirent.name for dirent in await valid.read()], ['.', '..', 'sock'])
