from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.tasks.stdin_bootstrap import *

from rsyscall.tests.utils import do_async_things
from rsyscall import Command, AsyncChildPid, Process

class TestStdinboot(TrioTestCase):
    command: Command
    local_child: AsyncChildPid
    remote: Process

    @classmethod
    async def asyncSetUpClass(cls) -> None:
        path = await stdin_bootstrap_path_with_nix(cls.process)
        cls.command = Command(path, ['rsyscall-stdin-bootstrap'], {})
        cls.local_child, cls.remote = await stdin_bootstrap(cls.process, cls.command)

    @classmethod
    async def asyncTearDownClass(cls) -> None:
        await cls.remote.exit(0)
        await cls.local_child.wait()

    async def test_async(self) -> None:
        await do_async_things(self, self.remote.epoller, self.remote)

    async def test_nest(self) -> None:
        child, new_process = await stdin_bootstrap(self.remote, self.command)
        async with child:
            await do_async_things(self, new_process.epoller, new_process)

    async def test_nest_multiple(self) -> None:
        for i in range(5):
            child = await self.remote.fork()
            await do_async_things(self, child.epoller, child)
            await child.exit(0)
