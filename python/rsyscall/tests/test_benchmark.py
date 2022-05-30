from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import Process, Command
from rsyscall.sys.wait import W
import typing as t
import cProfile
import pstats

async def rsys_run(parent: Process, cmd: Command, count: int) -> None:
    for _ in range(count):
        process = await parent.fork()
        child = await process.exec(cmd)
        await child.waitpid(W.EXITED)

class TestBenchmark(TrioTestCase):
    async def test_bench(self):
        "Run a simple clone and exec case inside cProfile (without asserting the results)"

        await self.process.environ.as_arglist(self.process.task)
        cmd = (await self.process.environ.which("echo")).args("-n")
        pr = cProfile.Profile()
        warm_up_runs = 1
        real_runs = 1
        await rsys_run(self.process, cmd, warm_up_runs)
        pr.enable()
        await rsys_run(self.process, cmd, real_runs)
        pr.disable()
        # pr.print_stats(sort='cumtime')
        # ps = pstats.Stats(pr).strip_dirs().sort_stats('cumulative')
        # ps.print_callees()
