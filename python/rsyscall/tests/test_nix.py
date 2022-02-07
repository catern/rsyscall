from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.nix import *
from rsyscall.sched import CLONE
from rsyscall.stdlib import mkdtemp
import rsyscall._nixdeps.nix

class TestNix(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.parent, self.process = self.process, await self.process.fork()
        self.tmpdir = await mkdtemp(self.parent, "test_nix")
        await enter_nix_container(self.parent, rsyscall._nixdeps.nix.closure, self.process, self.tmpdir)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_true(self) -> None:
        true = (await deploy(self.process, rsyscall._nixdeps.coreutils.closure)).bin('true')
        await self.process.run(true)

    async def test_with_daemon(self) -> None:
        nix_daemon = (await deploy(self.process, rsyscall._nixdeps.nix.closure)).bin("nix-daemon")
        nd_child = await (await self.process.fork()).exec(nix_daemon)
        self.process.environ['NIX_REMOTE'] = 'daemon'
        true = (await deploy(self.process, rsyscall._nixdeps.coreutils.closure)).bin('true')
        await self.process.run(true)
        await nd_child.kill()
        await nd_child.wait()
