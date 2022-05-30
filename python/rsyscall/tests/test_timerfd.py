from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sys.timerfd import *

class TestTimerfd(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.fd = await self.process.task.timerfd_create(CLOCK.REALTIME)

    async def asyncTearDown(self) -> None:
        await self.fd.close()

    async def test(self) -> None:
        await self.fd.timerfd_settime(
            TFD_TIMER.NONE, await self.process.task.ptr(Itimerspec(Timespec(0, 0), Timespec(0, 1))))
        await self.fd.timerfd_gettime(await self.process.task.malloc(Itimerspec))
