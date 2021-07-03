from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.tasks.stdin_bootstrap import *

from rsyscall import local_thread

from rsyscall.tests.utils import do_async_things
from rsyscall.command import Command

class TestStdinboot(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        path = await stdin_bootstrap_path_with_nix(self.local)
        self.command = Command(path, ['rsyscall-stdin-bootstrap'], {})
        self.local_child, self.remote = await stdin_bootstrap(self.local, self.command)

    async def asyncTearDown(self) -> None:
        await self.local_child.kill()

    async def test_exit(self) -> None:
        await self.remote.exit(0)

    async def test_async(self) -> None:
        await do_async_things(self, self.remote.epoller, self.remote)

    async def test_nest(self) -> None:
        child, new_thread = await stdin_bootstrap(self.remote, self.command)
        async with child:
            await do_async_things(self, new_thread.epoller, new_thread)

    async def test_nest_multiple(self) -> None:
        for i in range(5):
            child = await self.remote.clone()
            await do_async_things(self, child.epoller, child)
            await child.exit(0)
