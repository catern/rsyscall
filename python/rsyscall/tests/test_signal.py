from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.signal import *

class TestSignal(TrioTestCase):
    async def test_sigaction(self) -> None:
        sa = Sigaction(Sighandler.DFL)
        ptr = await self.process.task.ptr(sa)
        await self.process.task.sigaction(SIG.WINCH, ptr, None)
        await self.process.task.sigaction(SIG.WINCH, None, ptr)
        out_sa = await ptr.read()
        self.assertEqual(sa.handler, out_sa.handler)
        self.assertEqual(sa.flags, out_sa.flags)
        self.assertEqual(sa.mask, out_sa.mask)
        self.assertEqual(sa.restorer, out_sa.restorer)

    # TODO test_signalblock
    # async def test_signalblock(self) -> None:
    #     pass
