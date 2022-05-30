from __future__ import annotations
from rsyscall.tests.trio_test_case import TrioTestCase
from arepl import *
from rsyscall.wish import serve_repls
from rsyscall.stdlib import mkdtemp
from rsyscall.sys.socket import AF, SOCK
from rsyscall.sys.un import SockaddrUn
import unittest
import typing as t

class TestREPL(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(self.process, "test_stub")
        self.sock_path = self.tmpdir/"repl.sock"

    async def test_repl(self) -> None:
        sockfd = await self.process.make_afd(await self.process.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        addr = await self.process.task.ptr(await SockaddrUn.from_path(self.process, self.sock_path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        clientfd = await self.process.make_afd(await self.process.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        await clientfd.connect(addr)
        await clientfd.write_all_bytes(b"foo = 11\n")
        await clientfd.write_all_bytes(b"return foo * 2\n")
        ret = await serve_repls(sockfd, {'locals': locals()}, int, "hello")
        self.assertEqual(ret, 22)
