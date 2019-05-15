from __future__ import annotations
import unittest

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.tests.test_io import do_async_things
from rsyscall.epoller import EpollCenter

class TestFork(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.thr = await self.local.fork()

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_exit(self) -> None:
        await self.thr.exit(0)

    async def test_nest_exit(self) -> None:
        thread = await self.thr.fork()
        async with thread:
            await thread.exit(0)

    async def test_async(self) -> None:
        epoller = await EpollCenter.make_root(self.thr.ram, self.thr.task)
        await do_async_things(self, epoller, self.thr)

    async def test_nest_async(self) -> None:
        thread = await self.thr.fork()
        async with thread:
            epoller = await EpollCenter.make_root(thread.ram, thread.task)
            await do_async_things(self, epoller, thread)

    async def test_unshare_async(self) -> None:
        await self.thr.unshare_files()
        thread = await self.thr.fork()
        async with thread:
            epoller = await EpollCenter.make_root(thread.ram, thread.task)
            await thread.unshare_files()
            await do_async_things(self, epoller, thread)

    async def test_exec(self) -> None:
        child = await self.thr.exec(self.thr.environ.sh.args('-c', 'true'))
        await child.check()

    async def test_mkdtemp(self) -> None:
        async with (await self.thr.mkdtemp()):
            pass
