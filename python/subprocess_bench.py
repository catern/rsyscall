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
from rsyscall.sched import CLONE

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
    cmd = await local.thread.environ.which('cat')
    await local.thread.environ.as_arglist(local.thread.ram)
    cwd = await local.thread.ptr(Path("/dev"))
    async def subp_run() -> None:
        popen = subprocess.Popen([cmd.executable_path, './null'], cwd=cwd.value)
        popen.wait()
    async def rsys_run() -> None:
        child = await local.thread.clone()
        await child.task.chdir(cwd)
        child_proc = await child.execv(cmd.executable_path, [cmd.executable_path, "./null"])
        await child_proc.waitpid(W.EXITED)
        await child.close()
    if mode == 'subprocess':
        run = subp_run
    elif mode == 'rsyscall':
        run = rsys_run
    elif mode == 'nest':
        nesting_child = await local.thread.clone()
        async def run() -> None:
            child = await nesting_child.clone()
            await child.task.chdir(cwd)
            child_proc = await child.execv(cmd.executable_path, [cmd.executable_path, "./null"])
            await child_proc.waitpid(W.EXITED)
            await child.close()
    elif mode == 'nestnest':
        first_nesting_child = await local.thread.clone()
        second_nesting_child = await first_nesting_child.clone()
        async def run() -> None:
            child = await second_nesting_child.clone()
            await child.task.chdir(cwd)
            child_proc = await child.execv(cmd.executable_path, [cmd.executable_path, "./null"])
            await child_proc.waitpid(W.EXITED)
            await child.close()
    elif mode == 'flags':
        async def run() -> None:
            child = await local.thread.clone(CLONE.NEWPID|CLONE.NEWNS)
            await child.task.chdir(cwd)
            child_proc = await child.execv(cmd.executable_path, [cmd.executable_path, "./null"])
            await child_proc.waitpid(W.EXITED)
            await child.close()
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
    parser.add_argument('--run-benchmark', choices=['subprocess', 'rsyscall', 'nest', 'nestnest', 'flags'])
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
        return [(i, await run_many(mode, 10**i)) for i in range(3)]
    subprocess = [(0, 1662.7047061920166), (1, 1666.396141052246), (2, 1668.2496070861816), (3, 1670.4914569854736), (4, 2006.0789585113525), (5, 10209.86270904541), (6, 48588.73701095581)]
    rsyscall = [(0, 2229.5007705688477), (1, 2258.697509765625), (2, 2234.3757152557373), (3, 2238.978862762451), (4, 2196.8472003936768), (5, 2204.909563064575), (6, 2199.6195316314697)]
    subprocess = await get_data("subprocess")
    print("subprocess =", subprocess)
    rsyscall = await get_data("rsyscall")
    print("rsyscall =", rsyscall)
    nest = await get_data("nest")
    print("nest =", nest)
    nestnest = await get_data("nestnest")
    print("nestnest =", nestnest)
    flags = await get_data("flags")
    print("flags =", flags)
    fig, ax = plt.subplots(figsize=(6.4,3.2))
    plt.xscale('log')
    plt.yscale('log')
    ax.plot([10**x for x, y in subprocess], [y for x, y in subprocess], 'o-', label="Python subprocess",
            linewidth=4, markersize=12)
    ax.plot([10**x for x, y in rsyscall], [y for x, y in rsyscall], '^-', label="rsyscall clone",
            linewidth=4, markersize=12)
    ax.plot([10**x for x, y in nest], [y for x, y in nest], '^-', label="rsyscall nest",
            linewidth=4, markersize=12)
    ax.plot([10**x for x, y in nestnest], [y for x, y in nestnest], '^-', label="rsyscall nestnest",
            linewidth=4, markersize=12)
    ax.plot([10**x for x, y in flags], [y for x, y in flags], '^-', label="rsyscall clone(NEWPID|NEWNS)",
            linewidth=4, markersize=12)
    ax.legend()
    
    ax.set(xlabel='Pages mapped in memory', ylabel='time (us)')
    ax.grid()
    
    fig.savefig("subprocess_bench.png")
    plt.show()


if __name__ == "__main__":
    trio.run(main)

