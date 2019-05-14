from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
from rsyscall.tasks.stdin_bootstrap import *

import rsyscall.tasks.local as local

from rsyscall.tests.test_io import do_async_things
from rsyscall.io import Command

class TestStdinboot(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = local.stdtask
        path = await stdin_bootstrap_path_from_store(local_store)
        self.command = Command(path, ['rsyscall-stdin-bootstrap'], {})
        self.local_child, self.remote_stdtask = await rsyscall_stdin_bootstrap(self.stdtask, self.command)

    async def asyncTearDown(self) -> None:
        await self.local_child.kill()

    async def test_exit(self) -> None:
        await self.remote_stdtask.exit(0)

    async def test_async(self) -> None:
        await do_async_things(self, self.remote_stdtask.epoller, self.remote_stdtask.ramthr)

    async def test_nest(self) -> None:
        child, new_stdtask = await rsyscall_stdin_bootstrap(self.remote_stdtask, self.command)
        async with child:
            await do_async_things(self, new_stdtask.epoller, new_stdtask.ramthr)
    
