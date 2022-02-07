from rsyscall.fcntl import O
from rsyscall.sched import CLONE
from rsyscall.tests.trio_test_case import TrioTestCase
import gc

class TestFS(TrioTestCase):
    async def test_fd_gc(self) -> None:
        "Verify that file descriptors actually get GC'd."
        gc.collect()
        await self.process.task.run_fd_table_gc()
        devnull = await self.process.ptr("/dev/null")
        first = int(await self.process.task.open(devnull, O.RDONLY))
        for _ in range(5):
            child = await self.process.clone(CLONE.FILES)
            for _ in range(50):
                await child.task.open(devnull, O.RDONLY)
        gc.collect()
        await self.process.task.run_fd_table_gc()
        last = int(await self.process.task.open(devnull, O.RDONLY))
        self.assertEqual(first, last)
