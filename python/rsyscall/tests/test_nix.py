from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.nix import *
from rsyscall.sched import CLONE
from rsyscall.stdlib import mkdtemp
import rsyscall._nixdeps.nix

class TestNix(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.parent, self.thr = self.thr, await self.thr.fork()
        self.tmpdir = await mkdtemp(self.parent)
        await enter_nix_container(self.parent, rsyscall._nixdeps.nix.closure, self.thr, self.tmpdir)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_hello(self) -> None:
        hello = (await deploy(self.thr, rsyscall._nixdeps.coreutils.closure)).bin('echo').args('hello world')
        await self.thr.run(hello)

    async def test_with_daemon(self) -> None:
        nix_daemon = (await deploy(self.thr, rsyscall._nixdeps.nix.closure)).bin("nix-daemon")
        nd_child = await (await self.thr.fork()).exec(nix_daemon)
        self.thr.environ['NIX_REMOTE'] = 'daemon'
        hello = (await deploy(self.thr, rsyscall._nixdeps.coreutils.closure)).bin('echo').args('hello world')
        await self.thr.run(hello)
