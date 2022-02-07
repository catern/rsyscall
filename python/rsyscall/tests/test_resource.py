from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sys.resource import *

class TestResource(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.process = await self.process.fork()

    async def asyncTearDown(self) -> None:
        await self.process.exit(0)

    async def test_rlimit(self) -> None:
        old_rlimit = await (await self.process.task.getrlimit(RLIMIT.FSIZE, await self.process.malloc(Rlimit))).read()
        rlimit = Rlimit(old_rlimit.cur - 1, old_rlimit.max - 1)
        await self.process.task.setrlimit(RLIMIT.FSIZE, await self.process.ptr(rlimit))
        new_rlimit = await (await self.process.task.getrlimit(RLIMIT.FSIZE, await self.process.malloc(Rlimit))).read()
        self.assertEqual(rlimit, new_rlimit)
        self.assertNotEqual(old_rlimit, new_rlimit)
