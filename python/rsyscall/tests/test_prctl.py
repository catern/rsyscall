import logging
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sys.prctl import *
logger = logging.getLogger(__name__)

class TestUser(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.process = await self.process.fork()

    async def asyncTearDown(self) -> None:
        await self.process.exit(0)

    async def test_name(self) -> None:
        namep = await self.process.task.prctl(PR.GET_NAME, await self.process.malloc(str, 16))
        logger.info("My initial name is %s", await namep.read())
        newname = "newname"
        await self.process.task.prctl(PR.SET_NAME, await self.process.ptr(newname))
        namep = await self.process.task.prctl(PR.GET_NAME, namep)
        self.assertEqual(newname, await namep.read())
