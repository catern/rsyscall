from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.unistd import Pipe
from rsyscall.fcntl import O
from rsyscall.sched import CLONE

class TestCat(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.cat = await self.thr.environ.which("cat")
        self.pipe_in = await (await self.thr.task.pipe(await self.thr.ram.malloc(Pipe))).read()
        self.pipe_out = await (await self.thr.task.pipe(await self.thr.ram.malloc(Pipe))).read()
        process = await self.thr.clone()
        await process.task.inherit_fd(self.pipe_in.read).dup2(process.stdin)
        await process.task.inherit_fd(self.pipe_out.write).dup2(process.stdout)
        self.child = await process.exec(self.cat)

    async def test_cat_pipe(self) -> None:
        in_data = await self.thr.ram.ptr(b"hello")
        written, _ = await self.pipe_in.write.write(in_data)
        valid, _ = await self.pipe_out.read.read(written)
        self.assertEqual(in_data.value, await valid.read())
        
        await self.pipe_in.write.close()
        await self.child.check()

    async def test_cat_async(self) -> None:
        stdin = await self.thr.make_afd(self.pipe_in.write, set_nonblock=True)
        stdout = await self.thr.make_afd(self.pipe_out.read, set_nonblock=True)
        in_data = await self.thr.ram.ptr(b"hello")
        written, _ = await stdin.write(in_data)
        valid, _ = await stdout.read(written)
        self.assertEqual(in_data.value, await valid.read())
        
        await self.pipe_in.write.close()
        await self.child.check()
