import logging
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.sys.prctl import *
logger = logging.getLogger(__name__)

class TestUser(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.thr = await self.local.clone()

    async def asyncTearDown(self) -> None:
        await self.thr.exit(0)

    async def test_name(self) -> None:
        namep = await self.thr.task.prctl(PR.GET_NAME, await self.thr.malloc(str, 16))
        logger.info("My initial name is %s", await namep.read())
        newname = "newname"
        await self.thr.task.prctl(PR.SET_NAME, await self.thr.ptr(newname))
        namep = await self.thr.task.prctl(PR.GET_NAME, namep)
        self.assertEqual(newname, await namep.read())
