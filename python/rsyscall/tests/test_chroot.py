from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.stdlib import mkdtemp
from rsyscall.sys.mount import MS
from rsyscall.sched import CLONE
from rsyscall.unistd import O
import unittest

class TestChroot(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(self.process)
        self.process = await self.process.clone(CLONE.NEWUSER|CLONE.NEWNS)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_basic(self) -> None:
        await self.process.mkdir(self.tmpdir/"proc")
        await self.process.mount("/proc", self.tmpdir/"proc", "", MS.BIND, "")
        await self.process.task.chroot(await self.process.ptr(self.tmpdir))
        await self.process.task.open(await self.process.ptr("/proc/self"), O.RDONLY)
