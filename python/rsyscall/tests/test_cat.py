from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local

from rsyscall.struct import Bytes
from rsyscall.unistd import Pipe
from rsyscall.fcntl import O

class TestCat(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.cat = await self.thr.environ.which("cat")

    async def test_cat(self) -> None:
        pipe_in = await (await self.thr.task.pipe(await self.thr.ram.malloc_struct(Pipe), O.CLOEXEC)).read()
        pipe_out = await (await self.thr.task.pipe(await self.thr.ram.malloc_struct(Pipe), O.CLOEXEC)).read()
        thread = await self.thr.fork()
        await thread.unshare_files_and_replace({
            thread.stdin: pipe_in.read,
            thread.stdout: pipe_out.write,
        })
        child = await thread.exec(self.cat)

        in_data = await self.thr.ram.to_pointer(Bytes(b"hello"))
        written, _ = await pipe_in.write.write(in_data)
        valid, _ = await pipe_out.read.read(written)
        self.assertEqual(in_data.value, await valid.read())
        
        await pipe_in.write.close()
        await child.check()
