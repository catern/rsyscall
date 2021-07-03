from __future__ import annotations
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from arepl import *
from rsyscall.wish import serve_repls
from rsyscall.stdlib import mkdtemp
from rsyscall.sys.socket import AF, SOCK
from rsyscall.sys.un import SockaddrUn
import unittest
import typing as t

class TestREPL(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread
        self.tmpdir = await mkdtemp(self.thr, "test_stub")
        self.sock_path = self.tmpdir/"repl.sock"

    async def test_repl(self) -> None:
        sockfd = await self.thr.make_afd(await self.thr.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        addr = await self.thr.ram.ptr(await SockaddrUn.from_path(self.thr, self.sock_path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        clientfd = await self.thr.make_afd(await self.thr.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        await clientfd.connect(addr)
        await clientfd.write_all_bytes(b"foo = 11\n")
        await clientfd.write_all_bytes(b"return foo * 2\n")
        ret = await serve_repls(sockfd, {'locals': locals()}, int, "hello")
        self.assertEqual(ret, 22)
