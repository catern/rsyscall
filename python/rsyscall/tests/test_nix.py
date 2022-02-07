from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.nix import *
from rsyscall.sched import CLONE
from rsyscall.stdlib import mkdtemp
import rsyscall._nixdeps.nix

class TestNix(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.parent, self.thr = self.thr, await self.thr.fork()
        self.tmpdir = await mkdtemp(self.parent, "test_nix")
        await enter_nix_container(self.parent, rsyscall._nixdeps.nix.closure, self.thr, self.tmpdir)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_true(self) -> None:
        true = (await deploy(self.thr, rsyscall._nixdeps.coreutils.closure)).bin('true')
        await self.thr.run(true)

    async def test_with_daemon(self) -> None:
        nix_daemon = (await deploy(self.thr, rsyscall._nixdeps.nix.closure)).bin("nix-daemon")
        nd_child = await (await self.thr.fork()).exec(nix_daemon)
        self.thr.environ['NIX_REMOTE'] = 'daemon'
        true = (await deploy(self.thr, rsyscall._nixdeps.coreutils.closure)).bin('true')
        await self.thr.run(true)
        await nd_child.kill()
        await nd_child.wait()
