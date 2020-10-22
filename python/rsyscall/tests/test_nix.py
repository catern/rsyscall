from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread

from rsyscall.nix import *
from rsyscall.sched import CLONE
from rsyscall.stdlib import mkdtemp

class TestNix(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(local_thread)
        self.thr = await local_thread.clone()
        self.store = await enter_nix_container(local_store, self.thr, self.tmpdir.path)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_hello(self) -> None:
        hello = await self.store.bin(hello_nixdep, "hello")
        await self.thr.run(hello)

    async def test_with_daemon(self) -> None:
        nix_daemon = await self.store.bin(nix, "nix-daemon")
        nd_child = await (await self.thr.clone()).exec(nix_daemon)
        self.thr.environ['NIX_REMOTE'] = 'daemon'
        hello = await self.store.bin(hello_nixdep, "hello")
        await self.thr.run(hello)
