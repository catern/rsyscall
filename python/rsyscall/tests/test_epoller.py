from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.epoller import *
import trio
import unittest

from rsyscall.tests.utils import do_async_things

# import logging
# logging.basicConfig(level=logging.INFO)


class TestEpoller(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread

    async def test_local(self) -> None:
        await do_async_things(self, self.thr.epoller, self.thr)

    async def test_multi(self) -> None:
        await do_async_things(self, self.thr.epoller, self.thr, -1)
        async with trio.open_nursery() as nursery:
            for i in range(2):
                await nursery.start(do_async_things, self, self.thr.epoller, self.thr, i)
                # await do_async_things(self, self.thr.epoller, self.thr)

    async def test_thread_epoller(self) -> None:
        thread = await self.thr.clone()
        await do_async_things(self, thread.epoller, thread)

    async def test_thread_root_epoller(self) -> None:
        thread = await self.thr.clone()
        epoller = await Epoller.make_root(thread.ram, thread.task)
        await do_async_things(self, epoller, thread)

    async def test_thread_two(self) -> None:
        thread = await self.thr.clone()
        epoller = thread.epoller
        async with trio.open_nursery() as nursery:
            await nursery.start(do_async_things, self, epoller, thread)
            await nursery.start(do_async_things, self, thread.epoller, thread)

    @unittest.skip("oops we broke this")
    async def test_afd_with_handle(self):
        pipe = await self.thr.pipe()
        afd = await self.thr.make_afd(pipe.write)
        new_afd = afd.with_handle(pipe.write)
        await new_afd.write_all_bytes(b'foo')
