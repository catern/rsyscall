from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.handle.pointer import UseAfterFreeError

class TestPointer(TrioTestCase):
    async def test_use_after_free_ptr(self) -> None:
        buf = await self.process.malloc(bytes, 16)
        buf.free()
        with self.assertRaises(UseAfterFreeError):
            buf.near
        str(buf)

    async def test_use_after_free_allocation(self) -> None:
        buf = await self.process.malloc(bytes, 16)
        buf.allocation.free()
        with self.assertRaises(UseAfterFreeError):
            buf.near
        buf = await self.process.ptr(b'foo')
        buf.allocation.free()
        with self.assertRaises(UseAfterFreeError):
            buf.near
        str(buf)
