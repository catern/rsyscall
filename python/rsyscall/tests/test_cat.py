from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local

from rsyscall.unistd import Pipe
from rsyscall.fcntl import O

class TestCat(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.cat = await self.thr.environ.which("cat")
        self.pipe_in = await (await self.thr.task.pipe(await self.thr.ram.malloc_struct(Pipe))).read()
        self.pipe_out = await (await self.thr.task.pipe(await self.thr.ram.malloc_struct(Pipe))).read()
        thread = await self.thr.fork()
        await thread.unshare_files_and_replace({
            thread.stdin: self.pipe_in.read,
            thread.stdout: self.pipe_out.write,
        })
        self.child = await thread.exec(self.cat)

    async def test_cat_pipe(self) -> None:
        in_data = await self.thr.ram.ptr(b"hello")
        written, _ = await self.pipe_in.write.write(in_data)
        valid, _ = await self.pipe_out.read.read(written)
        self.assertEqual(in_data.value, await valid.read())
        
        await self.pipe_in.write.close()
        await self.child.check()

    async def test_cat_async(self) -> None:
        stdin = await self.thr.make_afd(self.pipe_in.write, nonblock=False)
        stdout = await self.thr.make_afd(self.pipe_out.read, nonblock=False)
        in_data = await self.thr.ram.ptr(b"hello")
        written, _ = await stdin.write(in_data)
        valid, _ = await stdout.read(written)
        self.assertEqual(in_data.value, await valid.read())
        
        await self.pipe_in.write.close()
        await self.child.check()
