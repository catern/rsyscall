from __future__ import annotations
from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from arepl import *
from rsyscall.wish import serve_repls
from rsyscall.sys.socket import AF, SOCK, Address
from rsyscall.sys.un import SockaddrUn
import unittest
import typing as t

class TestREPL(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.tmpdir = await self.thr.mkdtemp("test_stub")
        self.sock_path = self.tmpdir.path/"repl.sock"

    async def test_repl(self) -> None:
        sockfd = await self.thr.make_afd(
            await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
        addr = await self.thr.ram.to_pointer(await SockaddrUn.from_path(self.thr, self.sock_path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        clientfd = await self.thr.make_afd(
            await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
        await clientfd.connect(addr)
        await clientfd.write_all_bytes(b"foo = 11\n")
        await clientfd.write_all_bytes(b"return foo * 2\n")
        ret = await serve_repls(sockfd, {'locals': locals()}, int, "hello")
        self.assertEqual(ret, 22)
