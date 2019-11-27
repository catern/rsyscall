from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.handle.pointer import UseAfterFreeError

class TestSocket(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread

    async def test_use_after_free_ptr(self) -> None:
        buf = await self.thr.malloc(bytes, 16)
        buf.free()
        with self.assertRaises(UseAfterFreeError):
            buf.near
        str(buf)

    async def test_use_after_free_allocation(self) -> None:
        buf = await self.thr.malloc(bytes, 16)
        buf.allocation.free()
        with self.assertRaises(UseAfterFreeError):
            buf.near
        buf = await self.thr.ptr(b'foo')
        buf.allocation.free()
        with self.assertRaises(UseAfterFreeError):
            buf.near
        str(buf)
