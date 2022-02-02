from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sched import CpuSet

class TestEventfd(TrioTestCase):
    async def test(self) -> None:
        avail = await (await self.thr.task.sched_getaffinity(await self.thr.malloc(CpuSet))).read()
        with self.assertRaises(OSError, msg="calling setaffinity with an empty set should fail"):
            await self.thr.task.sched_setaffinity(await self.thr.ptr(CpuSet()))
        await self.thr.task.sched_setaffinity(await self.thr.ptr(CpuSet([list(avail)[0]])))
        await self.thr.task.sched_setaffinity(await self.thr.ptr(avail))
