from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.path import Path
from rsyscall.fcntl import O
from rsyscall.sys.prctl import *
from rsyscall.sys.capability import *
from rsyscall.sched import CLONE

class TestUser(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.thr = await self.local.clone(CLONE.NEWUSER)

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_ambient_caps(self) -> None:
        hdr_ptr = await self.thr.ram.ptr(CapHeader())
        data_ptr = await self.thr.ram.malloc(CapData)
        await self.thr.task.capget(hdr_ptr, data_ptr)
        data = await data_ptr.read()
        data.inheritable.add(CAP.SYS_ADMIN)
        data_ptr = await data_ptr.write(data)
        await self.thr.task.capset(hdr_ptr, data_ptr)
        await self.thr.task.prctl(PR.CAP_AMBIENT, PR_CAP_AMBIENT.RAISE, CAP.SYS_ADMIN)
