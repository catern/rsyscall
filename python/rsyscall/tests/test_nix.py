from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local

from rsyscall.nix import *
from rsyscall.misc import hello_nixdep
from rsyscall.struct import Bytes

class TestNix(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = await local.thread.fork()
        self.tmpdir = await self.thr.mkdtemp()
        self.store = await enter_nix_container(local_store, self.thr, self.tmpdir.path)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_hello(self) -> None:
        hello = await self.store.bin(hello_nixdep, "hello")
        await self.thr.run(hello)

    async def test_with_daemon(self) -> None:
        nix_daemon = await self.store.bin(nix, "nix-daemon")
        nd_child = await (await self.thr.fork()).exec(nix_daemon)
        self.thr.environ['NIX_REMOTE'] = 'daemon'
        hello = await self.store.bin(hello_nixdep, "hello")
        await self.thr.run(hello)
