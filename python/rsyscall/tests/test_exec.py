from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
from rsyscall.tasks.exec import *

from rsyscall import local_thread

from rsyscall.tests.utils import assert_thread_works
from rsyscall.sched import CLONE
import unittest

class TestExec(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.store = local_store
        self.executables = await RsyscallServerExecutable.from_store(self.store)
        self.child = await self.local.clone(CLONE.FILES)
        await rsyscall_exec(self.child, self.executables)

    async def asyncTearDown(self) -> None:
        await self.child.close()

    async def test_exit(self) -> None:
        await self.child.exit(0)

    async def test_basic(self) -> None:
        await assert_thread_works(self, self.child)
        grandchild = await self.child.clone()
        await assert_thread_works(self, grandchild)

    @unittest.skip("This is broken for some reason")
    async def test_nest(self) -> None:
        thread = await self.child.clone(CLONE.FILES)
        async with thread:
            await rsyscall_exec(self.child, thread, self.executables)
            await assert_thread_works(self, thread)
    
