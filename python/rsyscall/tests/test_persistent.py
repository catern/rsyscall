from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.io
from rsyscall.nix import local_store
import rsyscall.tasks.local as local
from rsyscall.tasks.persistent import *
from rsyscall.tasks.ssh import make_local_ssh

class TestPersistent(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = local.stdtask
        self.store = local_store
        self.tmpdir = await self.stdtask.mkdtemp("test_stub")
        self.sock_path = self.tmpdir.path/"persist.sock"
        self.task = self.stdtask.task.base
        self.ram = self.stdtask.ram

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_exit(self) -> None:
        per_stdtask, connection = await fork_persistent(self.stdtask, self.sock_path)
        await connection.reconnect(self.stdtask)
        await per_stdtask.unshare_files()
        await per_stdtask.exit(0)

    async def test_nest_exit(self) -> None:
        per_stdtask, connection = await fork_persistent(self.stdtask, self.sock_path)
        thread = await per_stdtask.fork()
        async with thread:
            await connection.reconnect(self.stdtask)
            await thread.exit(0)

    async def test_ssh(self) -> None:
        host = await make_local_ssh(self.stdtask, self.store)
        local_child, remote_stdtask = await host.ssh(self.stdtask)
        per_stdtask, connection = await fork_persistent(remote_stdtask, self.sock_path)
        await per_stdtask.unshare_files()
        await connection.reconnect(remote_stdtask)
        await per_stdtask.exit(0)
