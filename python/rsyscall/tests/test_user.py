from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.fcntl import O
from rsyscall.sys.prctl import *
from rsyscall.sys.capability import *
from rsyscall.sched import CLONE

class TestUser(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.thr = await self.local.clone(CLONE.NEWUSER)

    async def asyncTearDown(self) -> None:
        await self.thr.exit(0)

    async def test_ambient_caps(self) -> None:
        hdr = await self.thr.ptr(CapHeader())
        data_ptr = await self.thr.task.capget(hdr, await self.thr.malloc(CapData))
        data = await data_ptr.read()
        data.inheritable.add(CAP.SYS_ADMIN)
        await self.thr.task.capset(hdr, await data_ptr.write(data))
        await self.thr.task.prctl(PR.CAP_AMBIENT, PR_CAP_AMBIENT.RAISE, CAP.SYS_ADMIN)
