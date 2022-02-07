from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.fcntl import O
from rsyscall.sys.prctl import *
from rsyscall.sys.capability import *
from rsyscall.sched import CLONE

class TestUser(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.process = await self.process.clone(CLONE.NEWUSER)

    async def asyncTearDown(self) -> None:
        await self.process.exit(0)

    async def test_ambient_caps(self) -> None:
        hdr = await self.process.ptr(CapHeader())
        data_ptr = await self.process.task.capget(hdr, await self.process.malloc(CapData))
        data = await data_ptr.read()
        data.inheritable.add(CAP.SYS_ADMIN)
        await self.process.task.capset(hdr, await data_ptr.write(data))
        await self.process.task.prctl(PR.CAP_AMBIENT, PR_CAP_AMBIENT.RAISE, CAP.SYS_ADMIN)
