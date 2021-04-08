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
from rsyscall.unistd import SEEK, OK
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
    cwd = await local.thread.ptr(Path("/dev"))
    async def subp_run() -> None:
        popen = subprocess.Popen([cmd.executable_path])
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
    parser.add_argument('--run-benchmark', choices=['subprocess', 'rsyscall', 'fork', 'posix_spawn'])
    parser.add_argument('--mmaps', type=int, default=0)
    parser.add_argument('--no-use-setpriority', help="don't setpriority before benchmarking; doing that requires privileges,"
                        " which are attained by running the benchmark with sudo (handled internally)",
                        action='store_true')
    parser.add_argument('num_runs', type=int)

    args = parser.parse_args()

    if args.run_benchmark:
        print(await run_benchmark(args.run_benchmark, args.mmaps))
        return

    native_cmd = Command(Path("./a.out"), ["./a.out"], {})
    await local.thread.task.access(await local.thread.ptr(native_cmd.executable_path), OK.X)
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
        if mode in ['fork', 'posix_spawn']:
            proc = await child.exec(native_cmd.args(mode, str(mmaps)))
        else:
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
            print(mode, mmaps, "time per call", data)
            time = float(data)*1000*1000
            times.append(time)
        return(mean(times))
    async def get_data(mode: str) -> t.List[t.Tuple[int, int]]:
        return [(i, await run_many(mode, 10**i)) for i in range(7)]
    subprocess = [(0, 1223.6576080322266), (1, 1360.4254722595215), (2, 1305.1199913024902), (3, 1335.4859352111816), (4, 1655.7302474975586), (5, 8514.136791229248), (6, 79850.49486160278)]
    rsyscall = [(0, 2229.5007705688477), (1, 2258.697509765625), (2, 2234.3757152557373), (3, 2238.978862762451), (4, 2196.8472003936768), (5, 2204.909563064575), (6, 2199.6195316314697)]
    fork = [(0, 452.85), (1, 460.3), (2, 459.5), (3, 505.25), (4, 829.2), (5, 6555.9), (6, 77967.5)]
    posix_spawn = [(0, 440.1), (1, 449.2), (2, 436.75), (3, 450.6), (4, 437.45000000000005), (5, 439.25), (6, 435.65)]
    # subprocess = await get_data("subprocess")
    # rsyscall = await get_data("rsyscall")
    # fork = await get_data("fork")
    # posix_spawn = await get_data("posix_spawn")
    print("subprocess =", subprocess)
    print("rsyscall =", rsyscall)
    print("fork =", fork)
    print("posix_spawn =", posix_spawn)
    fig, ax = plt.subplots(figsize=(6.4,3.2))
    plt.xscale('log')
    plt.yscale('log')
    ax.plot([10**x for x, y in rsyscall], [y for x, y in rsyscall], '^-', label="rsyscall clone",
            linewidth=4, markersize=12)
    ax.plot([10**x for x, y in subprocess], [y for x, y in subprocess], 'o-', label="Python subprocess",
            linewidth=4, markersize=12)
    ax.plot([10**x for x, y in fork], [y for x, y in fork], 'P-', label="C fork",
            linewidth=4, markersize=12)
    ax.plot([10**x for x, y in posix_spawn], [y for x, y in posix_spawn], 'D-', label="C posix_spawn",
            linewidth=4, markersize=12)
    ax.legend()
    
    ax.set(xlabel='Pages mapped in memory', ylabel='time (us)')
    ax.grid()
    fig.tight_layout()
    
    fig.savefig("subprocess_bench.png")
    # plt.show()


if __name__ == "__main__":
    trio.run(main)

