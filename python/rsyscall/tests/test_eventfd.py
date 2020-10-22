from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.sys.eventfd import *
from rsyscall.struct import Int64

class TestEventfd(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread
        self.fd = await self.thr.task.eventfd(0)

    async def asyncTearDown(self) -> None:
        await self.fd.close()

    async def test(self) -> None:
        inval = Int64(10)
        written, _ = await self.fd.write(await self.thr.ram.ptr(inval))
        read, _ = await self.fd.read(written)
        self.assertEqual(inval, await read.read())
