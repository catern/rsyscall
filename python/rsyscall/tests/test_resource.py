from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.sys.resource import *

class TestResource(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = await local_thread.clone()

    async def asyncTearDown(self) -> None:
        await self.thr.exit(0)

    async def test_rlimit(self) -> None:
        old_rlimit = await (await self.thr.task.getrlimit(RLIMIT.FSIZE, await self.thr.malloc(Rlimit))).read()
        rlimit = Rlimit(old_rlimit.cur - 1, old_rlimit.max - 1)
        await self.thr.task.setrlimit(RLIMIT.FSIZE, await self.thr.ptr(rlimit))
        new_rlimit = await (await self.thr.task.getrlimit(RLIMIT.FSIZE, await self.thr.malloc(Rlimit))).read()
        self.assertEqual(rlimit, new_rlimit)
        self.assertNotEqual(old_rlimit, new_rlimit)
