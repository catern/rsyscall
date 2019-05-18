from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.tasks.exec import spawn_exec

from rsyscall.nix import local_store
from rsyscall.tests.utils import assert_thread_works

class TestFork(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.store = local_store
        self.thr = await self.local.fork(newuser=True, newpid=True, fs=False, sighand=False)

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_spawn(self) -> None:
        thread = await spawn_exec(self.thr, self.store)
        async with thread:
            await assert_thread_works(self, thread)
