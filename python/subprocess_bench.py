import time
import sys
import os
try:
    import trio
except:
    # ohhhh it's getting cleared by sudooooo
    # got it.
    print(os.environ, file=sys.stderr)
    exit(1)
import subprocess
import rsyscall.tasks.local as local
import sys
from rsyscall.sys.wait import W
from rsyscall import Command, Path

import rsyscall.nix as nix
from rsyscall.tasks.stdin_bootstrap import stdin_bootstrap, stdin_bootstrap_path_from_store
from rsyscall.unistd import SEEK
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.resource import PRIO
from statistics import mean
import csv
import argparse
from dataclasses import dataclass

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import typing as t

import cProfile

async def run_benchmark(mode: str, mmaps: int) -> t.Tuple[int, int]:
    for _ in range(mmaps):
        # set POPULATE so it actually gets faulted in; if it isn't
        # already in the page tables, there's no slowdown
        await local.thread.task.mmap(4096, PROT.READ|PROT.WRITE, MAP.PRIVATE|MAP.ANONYMOUS|MAP.POPULATE)
    cmd = await local.thread.environ.which('true')
    await local.thread.environ.as_arglist(local.thread.ram)
    async def subp_run() -> None:
        popen = subprocess.Popen([cmd.executable_path], preexec_fn=lambda: None)
        popen.wait()
    async def rsys_run() -> None:
        thread = await local.thread.clone()
        child = await thread.execv(cmd.executable_path, [cmd.executable_path])
        await child.waitpid(W.EXITED)
        await thread.close()
    if mode == 'subprocess':
        run = subp_run
    elif mode == 'rsyscall':
        run = rsys_run
    prep_count = 20
    count = 100
    before_prep = time.time()
    for _ in range(prep_count):
        await run()
    before = time.time()
    for _ in range(count):
        await run()
    after = time.time()
    prep_time = (before - before_prep)/prep_count
    real_time = (after - before)/count
    return real_time

async def main() -> None:
    parser = argparse.ArgumentParser(description='Do benchmarking of rsyscall vs subprocess.run')
    parser.add_argument('--run-benchmark', choices=['subprocess', 'rsyscall'])
    parser.add_argument('--mmaps', type=int, default=0)
    parser.add_argument('--no-use-setpriority', help="don't setpriority before benchmarking; doing that requires privileges,"
                        " which are attained by running the benchmark with sudo (handled internally)",
                        action='store_true')
    parser.add_argument('num_runs', type=int)

    args = parser.parse_args()

    if args.run_benchmark:
        print(await run_benchmark(args.run_benchmark, args.mmaps))
        return

    cmd = Command(Path(sys.executable), [sys.executable, __file__], {})
    if not args.no_use_setpriority:
        print("using sudo to use setpriority")
        stdin_bootstrap_path = await stdin_bootstrap_path_from_store(nix.local_store)
        proc, thread = await stdin_bootstrap(
            local.thread, (await local.thread.environ.which("sudo")).args('--preserve-env=PYTHONPATH', stdin_bootstrap_path))
    else:
        print("not using setpriority")
        thread = local.thread
    async def run_bench(mode: str, mmaps: int) -> str:
        fd = await thread.task.memfd_create(await thread.ptr(Path("data")))
        child = await thread.clone()
        if not args.no_use_setpriority:
            # POSIX's negative numbers are higher priority thing is weird; Linux's native
            # representation is that higher numbers are higher priority, glibc just adapts the
            # POSIXese to Linux. We just use the Linux thing.
            # strace - the betrayer! - claims that we're passing -20. lies!
            await child.task.setpriority(PRIO.PROCESS, 40)
        await child.inherit_fd(fd).dup2(child.stdout)
        proc = await child.exec(cmd.args(
            '--run-benchmark', mode,
            '--mmaps', str(mmaps), '0'))
        await child.close()
        await proc.check()
        await fd.lseek(0, SEEK.SET)
        raw_data = await thread.read_to_eof(fd)
        return raw_data.decode()
    async def run_many(mode: str, mmaps: int) -> float:
        print("run_many", mode, mmaps)
        times = []
        for _ in range(args.num_runs):
            data = await run_bench(mode, mmaps)
            time = float(data)*1000*1000
            times.append(time)
        return(mean(times))
    async def get_data(mode: str) -> t.List[t.Tuple[int, int]]:
        return [(i, await run_many(mode, 10**i)) for i in range(7)]
    subprocess = [(0, 1482.3333333333333), (1, 1530.3333333333333), (2, 1504.6666666666667), (3, 1665.3333333333333), (4, 1873.3333333333333)]
    rsyscall = [(0, 2249.3333333333335), (1, 2234.3333333333335), (2, 2261.6666666666665), (3, 2241.3333333333335), (4, 2321.3333333333335)]
    subprocess = await get_data("subprocess")
    rsyscall = await get_data("rsyscall")
    print("subprocess =", subprocess)
    print("rsyscall =", rsyscall)
    fig, ax = plt.subplots()
    plt.xscale('log')
    plt.yscale('log')
    ax.plot([10**x for x, y in subprocess], [y for x, y in subprocess], 'o-', label="Python subprocess")
    ax.plot([10**x for x, y in rsyscall], [y for x, y in rsyscall], '^-', label="rsyscall")
    ax.legend()
    
    ax.set(xlabel='Pages mapped in memory', ylabel='time (us)')
    ax.grid()
    
    fig.savefig("subprocess_bench.png")
    plt.show()


if __name__ == "__main__":
    trio.run(main)

