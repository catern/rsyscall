from __future__ import annotations
import unittest

from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.thread import do_cloexec_except

from rsyscall.tests.utils import do_async_things
from rsyscall.fcntl import O
from rsyscall.unistd import Pipe
from rsyscall.sched import CLONE

class TestMisc(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.process = await self.process.fork()

    async def asyncTearDown(self) -> None:
        await self.process.exit(0)

    async def test_do_cloexec_except(self) -> None:
        pipe = await (await self.process.task.pipe(await self.process.task.malloc(Pipe))).read()
        close_set = set([fd.near for fd in self.process.task.fd_handles])
        close_set.remove(pipe.read.near)
        await do_cloexec_except(self.process, close_set)

        data = await self.process.task.ptr(b"foo")
        with self.assertRaises(OSError):
            # this side was closed due to being cloexec
            await pipe.read.read(data)
        with self.assertRaises(BrokenPipeError):
            # this side is still open, but gets EPIPE
            await pipe.write.write(data)
