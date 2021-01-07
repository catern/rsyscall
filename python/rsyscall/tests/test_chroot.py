from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread

from rsyscall.stdlib import mkdtemp
from rsyscall.sys.mount import MS
from rsyscall.sched import CLONE
from rsyscall.unistd import O
import unittest

class TestChroot(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(local_thread)
        self.path = self.tmpdir.path
        self.thr = await local_thread.clone(CLONE.NEWUSER|CLONE.NEWNS)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_basic(self) -> None:
        await self.thr.mkdir(self.path/"proc")
        await self.thr.mount("/proc", self.path/"proc", "", MS.BIND, "")
        await self.thr.task.chroot(await self.thr.ptr(self.path))
        await self.thr.task.open(await self.thr.ptr("/proc/self"), O.RDONLY)
