from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sched import CpuSet

class TestEventfd(TrioTestCase):
    async def test(self) -> None:
        avail = await (await self.process.task.sched_getaffinity(await self.process.malloc(CpuSet))).read()
        with self.assertRaises(OSError, msg="calling setaffinity with an empty set should fail"):
            await self.process.task.sched_setaffinity(await self.process.ptr(CpuSet()))
        await self.process.task.sched_setaffinity(await self.process.ptr(CpuSet([list(avail)[0]])))
        await self.process.task.sched_setaffinity(await self.process.ptr(avail))
