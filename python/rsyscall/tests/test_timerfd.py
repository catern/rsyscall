from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.sys.timerfd import *

class TestTimerfd(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread
        self.fd = await self.thr.task.timerfd_create(CLOCK.REALTIME)

    async def asyncTearDown(self) -> None:
        await self.fd.close()

    async def test(self) -> None:
        await self.fd.timerfd_settime(
            TFD_TIMER.NONE, await self.thr.ram.ptr(Itimerspec(Timespec(0, 0), Timespec(0, 1))))
        await self.fd.timerfd_gettime(await self.thr.ram.malloc(Itimerspec))
