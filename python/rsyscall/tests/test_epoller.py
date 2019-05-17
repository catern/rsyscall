from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.epoller import *
import trio

from rsyscall.tests.test_io import do_async_things

class TestExec(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread

    async def test_thread_two(self) -> None:
        thread = await self.thr.fork()
        epoller = await EpollCenter.make_root(thread.ram, thread.task)
        async with trio.open_nursery() as nursery:
            nursery.start_soon(do_async_things, self, epoller, thread)
            nursery.start_soon(do_async_things, self, thread.epoller, thread)
