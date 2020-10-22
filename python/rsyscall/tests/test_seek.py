from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sys.stat import Stat
from rsyscall import local_thread

class TestSeek(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread
        self.file = await self.thr.task.memfd_create(await self.thr.ptr("file"))

    async def asyncTearDown(self) -> None:
        await self.file.close()

    async def test_preadwrite(self) -> None:
        stat = await (await self.file.fstat(await self.thr.malloc(Stat))).read()
        self.assertEqual(stat.size, 0)
        read, _ = await self.file.pread(await self.thr.malloc(bytes, 16), offset=0)
        self.assertEqual(read.size(), 0)
        read, _ = await self.file.pread(await self.thr.malloc(bytes, 16), offset=1)
        self.assertEqual(read.size(), 0)
        # we can write to an offset past the end
        data = b'abc'
        wrote, _ = await self.file.pwrite(await self.thr.ptr(data), offset=1)
        self.assertEqual(wrote.size(), len(data))
        # the data is written fine
        read, _ = await self.file.pread(await self.thr.malloc(bytes, 16), offset=1)
        self.assertEqual(await read.read(), data)
        # the earlier bytes are now zeros
        read, _ = await self.file.pread(await self.thr.malloc(bytes, 16), offset=0)
        self.assertEqual(await read.read(), b'\0' + data)
        # size is now 4
        stat = await (await self.file.fstat(await self.thr.malloc(Stat))).read()
        self.assertEqual(stat.size, 4)
