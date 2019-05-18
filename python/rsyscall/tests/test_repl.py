from __future__ import annotations
from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.repl import *
from rsyscall.wish import serve_repls
from rsyscall.sys.socket import AF, SOCK, Address
from rsyscall.sys.un import SockaddrUn
from rsyscall.handle import WrittenPointer
import unittest
import typing as t

T = t.TypeVar('T')
def await_pure(awaitable: t.Awaitable[T]) -> T:
    iterable = awaitable.__await__()
    try:
        next(iterable)
    except StopIteration as e:
        return e.value
    else:
        raise Exception("this awaitable actually is impure! it yields!")

class TestREPL(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.tmpdir = await self.thr.mkdtemp("test_stub")
        self.sock_path = self.tmpdir.path/"repl.sock"

    async def test_repl(self) -> None:
        sockfd = await self.thr.make_afd(
            await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
        addr: WrittenPointer[Address] = await self.thr.ram.to_pointer(await SockaddrUn.from_path(self.thr, self.sock_path))
        await sockfd.handle.bind(addr)
        await sockfd.handle.listen(10)
        clientfd = await self.thr.make_afd(
            await self.thr.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
        await clientfd.connect(addr)
        await clientfd.write_all_bytes(b"foo = 11\n")
        await clientfd.write_all_bytes(b"return foo * 2\n")
        ret = await serve_repls(sockfd, {'locals': locals()}, int, "hello")
        self.assertEqual(ret, 22)

class TestPure(unittest.TestCase):
    def test_add(self) -> None:
        async def test() -> None:
            repl = PureREPL({})
            async def eval(line: str) -> t.Any:
                result = await repl.add_line(line + '\n')
                if isinstance(result, ExpressionResult):
                    return result.value
                else:
                    raise Exception("unexpected", result)
            self.assertEqual(await eval('1'), 1)
            self.assertEqual(await eval('1+1'), 2)
            await repl.add_line('foo = 1\n')
            self.assertEqual(await eval('foo*4'), 4)
        await_pure(test())
