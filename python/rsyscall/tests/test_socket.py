from __future__ import annotations
import unittest

from rsyscall.trio_test_case import TrioTestCase

import rsyscall.tasks.local as local

from rsyscall.sys.socket import *
from rsyscall.sys.un import *
from rsyscall.struct import Bytes

import logging
logger = logging.getLogger(__name__)

class TestSocket(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.tmpdir = await self.thr.mkdtemp()
        self.path = self.tmpdir.path

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_listen(self) -> None:
        sockfd = await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.CLOEXEC)
        addr: WrittenPointer[Address] = await self.thr.ram.to_pointer(await SockaddrUn.from_path(self.thr, self.path/"sock"))
        await sockfd.bind(addr)
        await sockfd.listen(10)

        clientfd = await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.CLOEXEC)
        await clientfd.connect(addr)
        connfd = await sockfd.accept(SOCK.CLOEXEC)

    async def test_listen_async(self) -> None:
        sockfd = await self.thr.make_afd(await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
        addr: WrittenPointer[Address] = await self.thr.ram.to_pointer(await SockaddrUn.from_path(self.thr, self.path/"sock"))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)

        clientfd = await self.thr.make_afd(await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
        await clientfd.connect(addr)
        connfd, client_addr = await sockfd.accept_addr()
        logger.info("%s, %s", addr, client_addr)
        await connfd.close()
        await sockfd.close()
        await clientfd.close()

    async def test_listen_async_accept(self) -> None:
        sockfd = await self.thr.make_afd(await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
        addr: WrittenPointer[Address] = await self.thr.ram.to_pointer(await SockaddrUn.from_path(self.thr, self.path/"sock"))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)

        clientfd = await self.thr.make_afd(
            await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
        await clientfd.connect(addr)

        connfd_h, client_addr = await sockfd.accept_addr(SOCK.CLOEXEC|SOCK.NONBLOCK)
        connfd = await sockfd.thr.make_afd(connfd_h)
        logger.info("%s, %s", addr, client_addr)
        data = b"hello"
        await connfd.write_all_bytes(data)
        self.assertEqual(data, await clientfd.read_some_bytes())
        await connfd.close()
        await sockfd.close()
        await clientfd.close()
