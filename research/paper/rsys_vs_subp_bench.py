from rsyscall import local_thread
from rsyscall.sys.wait import W
import subprocess
import time
import typing as t

async def main():
    count = 100
    cmd = (await local_thread.environ.which("echo")).args("-n", "hello")
    prep = 5
    counts = ([], [], [], [])
    async def rsys_run() -> None:
        counts[0].append(time.time())
        child = await local_thread.clone()
        counts[1].append(time.time())
        proc = await child.exec(cmd)
        counts[2].append(time.time())
        await proc.waitpid(W.EXITED)
        counts[3].append(time.time())
    async def subp_run() -> None:
        subprocess.run(["echo", "-n", "hello"])
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

if __name__ == "__main__":
    trio.run(main)
