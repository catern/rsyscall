from rsyscall import local_thread
from rsyscall.fcntl import O
from rsyscall.sched import CLONE
from rsyscall.tests.trio_test_case import TrioTestCase
import gc

class TestFS(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread

    async def test_fd_gc(self) -> None:
        "Verify that file descriptors actually get GC'd."
        gc.collect()
        await self.thr.task.run_fd_table_gc()
        devnull = await self.thr.ptr("/dev/null")
        first = int(await self.thr.task.open(devnull, O.RDONLY))
        for _ in range(5):
            child = await self.thr.clone(CLONE.FILES)
            for _ in range(50):
                await child.task.open(devnull, O.RDONLY)
        gc.collect()
        await self.thr.task.run_fd_table_gc()
        last = int(await self.thr.task.open(devnull, O.RDONLY))
        self.assertEqual(first, last)
