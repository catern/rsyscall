from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
from rsyscall.tasks.exec import *

import rsyscall.tasks.local as local

from rsyscall.tests.test_io import do_async_things

class TestExec(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.store = local_store
        self.executables = await RsyscallServerExecutable.from_store(self.store)
        thread = await self.local.fork()
        await rsyscall_exec(self.local, await self.local.fork(), self.executables)
        self.child = thread

    async def asyncTearDown(self) -> None:
        await self.child.close()

    async def test_exit(self) -> None:
        await self.child.exit(0)

    async def test_basic(self) -> None:
        await do_async_things(self, self.child.epoller, self.child)

    async def test_spawn_nest(self) -> None:
        thread = await self.child.fork()
        async with thread:
            await rsyscall_exec(self.child, thread, self.executables)
            await do_async_things(self, thread.epoller, thread)
    
