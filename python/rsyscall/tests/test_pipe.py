from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.sys.socket import MSG
from rsyscall.sys.uio import IovecList
from rsyscall.unistd import Pipe
from rsyscall.fcntl import O

class TestPipe(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.pipe = await (await self.process.task.pipe(await self.process.malloc(Pipe))).read()

    async def asyncTearDown(self) -> None:
        await self.pipe.read.close()
        await self.pipe.write.close()

    async def test_read_write(self):
        in_data = await self.process.ptr(b"hello")
        written, _ = await self.pipe.write.write(in_data)
        valid, _ = await self.pipe.read.read(written)
        self.assertEqual(in_data.value, await valid.read())

    async def test_readv_writev(self):
        in_data = [b"hello", b"world"]
        iov = await self.process.ptr(IovecList([await self.process.ptr(data) for data in in_data]))
        written, partial, rest = await self.pipe.write.writev(iov)
        read, partial, rest = await self.pipe.read.readv(written)
        self.assertEqual(in_data, [await ptr.read() for ptr in read.value])

    async def test_recv(self) -> None:
        """Sadly, recv doesn't work on pipes

        Which is a major bummer, because that would allow us to avoid
        messing with O_NONBLOCK stuff

        """
        in_data = await self.process.ptr(b"hello")
        written, _ = await self.pipe.write.write(in_data)
        with self.assertRaises(OSError):
            valid, _ = await self.pipe.read.recv(written, MSG.NONE)
