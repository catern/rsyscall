from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
import os
import time
import subprocess
from rsyscall.sys.wait import W
import typing as t

class TestProc(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread

    async def test_fork(self) -> None:
        pid = os.fork()
        if pid == 0:
            try:
                os.execv(echo_path, [echo_path, "hello"])
            except OSError as e:
                await ipc.send(e)
                os.exit(1)
        else:
            result = await ipc.recv()
            if result.is_eof:
                print("successfully exec'd")
            elif result.is_exception:
                raise result.exception

    # equivalent to
    async def test_direct(self) -> None:
        child = self.local.clone()
        child.execv(echo_path, [echo_path, "Hello world!"])
        print("successfully exec'd")

    async def test_bench(self) -> None:
        count = 100
        cmd = (await self.local.environ.which("echo")).args("hello world")
        prep = 5
        counts = [[], [], [], []]
        async def rsys_run() -> None:
            counts[0].append(time.time())
            thread = await self.local.clone()
            counts[1].append(time.time())
            child = await thread.execv(cmd.executable_path, [cmd.executable_path, "-n", "hello"])
            counts[2].append(time.time())
            await child.waitpid(W.EXITED)
            counts[3].append(time.time())
            await thread.close()
        async def subp_run() -> None:
            subprocess.run(["echo", "hello world"])
        run = rsys_run
        # run = subp_run
        before_prep = time.time()
        for _ in range(prep):
            await run()
        before = time.time()
        for _ in range(count):
            await run()
        after = time.time()
        print("prep time", (before - before_prep)/prep)
        print("real time", (after - before)/count)
        
        def process(starts: t.List[float], ends: t.List[float]) -> float:
            return sum(end - start for start, end in zip(starts, ends))/count
        print("clone", process(counts[0], counts[1]))
        print("exec", process(counts[1], counts[2]))
        print("waitpid", process(counts[2], counts[3]))

import cProfile
import trio
async def prep() -> None:
    await local.thread.environ.as_arglist(local.thread.ram)
    return (await local.thread.environ.which("echo")).args("hello world")
cmd = trio.run(prep)
echo_path = cmd.executable_path
async def rsys_run() -> None:
    count = 500
    for _ in range(count):
        thread = await local.thread.clone()
        child = await thread.execv(cmd.executable_path, [cmd.executable_path, "-n", "hello"])
        await child.waitpid(W.EXITED)
        await thread.close()
        # print("free list length", len(local.thread.ram.allocator.shared_allocator.arenas[0].free_list))
import pstats
def main():
    pr = cProfile.Profile()
    pr.enable()    
    trio.run(rsys_run)
    pr.disable()
    pr.print_stats(sort='cumtime')
    # ps = pstats.Stats(pr).strip_dirs().sort_stats('cumulative')
    # ps.print_callees()
    print("arenas count", len(local.thread.ram.allocator.shared_allocator.arenas))
    return pr

if __name__ == "__main__":
    pr = main()
