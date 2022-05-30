from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sys.stat import Stat
from rsyscall.linux.fs import FI, FileCloneRange
import errno

class TestSeek(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.file = await self.process.task.memfd_create(await self.process.ptr("file"))

    async def asyncTearDown(self) -> None:
        await self.file.close()

    async def test_preadwrite(self) -> None:
        stat = await (await self.file.fstat(await self.process.malloc(Stat))).read()
        self.assertEqual(stat.size, 0)
        read, _ = await self.file.pread(await self.process.malloc(bytes, 16), offset=0)
        self.assertEqual(read.size(), 0)
        read, _ = await self.file.pread(await self.process.malloc(bytes, 16), offset=1)
        self.assertEqual(read.size(), 0)
        # we can write to an offset past the end
        data = b'abc'
        wrote, _ = await self.file.pwrite(await self.process.ptr(data), offset=1)
        self.assertEqual(wrote.size(), len(data))
        # the data is written fine
        read, _ = await self.file.pread(await self.process.malloc(bytes, 16), offset=1)
        self.assertEqual(await read.read(), data)
        # the earlier bytes are now zeros
        read, _ = await self.file.pread(await self.process.malloc(bytes, 16), offset=0)
        self.assertEqual(await read.read(), b'\0' + data)
        # size is now 4
        stat = await (await self.file.fstat(await self.process.malloc(Stat))).read()
        self.assertEqual(stat.size, 4)

    async def test_ficlonerange(self) -> None:
        await self.file.ftruncate(4096*2)
        with self.assertRaises(OSError) as cm:
            await self.file.ioctl(FI.CLONERANGE, await self.process.ptr(FileCloneRange(
                src_fd=self.file,
                src_offset=4096,
                src_length=4096,
                dest_offset=0,
            )))
        self.assertEqual(cm.exception.errno, errno.EOPNOTSUPP)
