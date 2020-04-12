from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall import Path

from rsyscall.sys.mount import MS
from rsyscall.sched import CLONE
from rsyscall.unistd import O

class TestChroot(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await local.thread.mkdtemp()
        self.path = self.tmpdir.path
        self.thr = await local.thread.clone(CLONE.NEWUSER|CLONE.NEWNS)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_basic(self) -> None:
        await self.thr.mkdir(self.path/"proc")
        await self.thr.mount(Path("/proc"), self.path/"proc", "", MS.BIND, "")
        await self.thr.task.chroot(await self.thr.ptr(self.path))
        await self.thr.task.open(await self.thr.ptr(Path("/proc/self")), O.RDONLY)
