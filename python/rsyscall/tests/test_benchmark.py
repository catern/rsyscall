from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread, Command
from rsyscall.sys.wait import W
import typing as t
import cProfile
import pstats

async def rsys_run(cmd: Command, count: int) -> None:
    for _ in range(count):
        thread = await local_thread.clone()
        child = await thread.exec(cmd)
        await child.waitpid(W.EXITED)

class TestBenchmark(TrioTestCase):
    async def test_bench(self):
        "Run a simple clone and exec case inside cProfile (without asserting the results)"

        await local_thread.environ.as_arglist(local_thread.ram)
        cmd = (await local_thread.environ.which("echo")).args("-n")
        pr = cProfile.Profile()
        warm_up_runs = 1
        real_runs = 1
        await rsys_run(cmd, warm_up_runs)
        pr.enable()
        await rsys_run(cmd, real_runs)
        pr.disable()
        # pr.print_stats(sort='cumtime')
        # ps = pstats.Stats(pr).strip_dirs().sort_stats('cumulative')
        # ps.print_callees()
