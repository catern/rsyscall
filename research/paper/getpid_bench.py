from dataclasses import dataclass
from rsyscall import Command, Path, local_thread
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.resource import PRIO
from rsyscall.sys.wait import W
from rsyscall.tasks.stdin_bootstrap import stdin_bootstrap, stdin_bootstrap_path_from_store
from rsyscall.unistd import SEEK
import statistics
import argparse
import os
import rsyscall.nix as nix
import subprocess
import sys
import time
import trio
import typing as t
import json

async def run_benchmark(mode: str, mmaps: int) -> t.Tuple[int, int]:
    for _ in range(mmaps):
        # set POPULATE so it actually gets faulted in; if it isn't
        # already in the page tables, there's no slowdown
        await local_thread.task.mmap(4096, PROT.READ|PROT.WRITE, MAP.PRIVATE|MAP.ANONYMOUS|MAP.POPULATE)
    cmd = await local_thread.environ.which('cat')
    await local_thread.environ.as_arglist(local_thread.ram)
    cwd = await local_thread.ptr(Path("/dev"))
    child = await local_thread.clone()
    nest1_child = await child.clone()
    nest2_child = await nest1_child.clone()
    async def subp_run() -> None:
        await local_thread.task.getpid()
    async def rsys_run() -> None:
        await child.task.getpid()
    async def nest_run() -> None:
        await child.task.getpid()
    if mode == 'subprocess':
        run = subp_run
    elif mode == 'rsyscall':
        run = rsys_run
    elif mode == 'nest':
        run = nest_run
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
    parser.add_argument('--run-benchmark', choices=['subprocess', 'rsyscall', 'nest'])
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
        print("using sudo to use setpriority", file=sys.stderr)
        stdin_bootstrap_path = await stdin_bootstrap_path_from_store(nix.local_store)
        proc, thread = await stdin_bootstrap(
            local_thread, (await local_thread.environ.which("sudo")).args('--preserve-env=PYTHONPATH', stdin_bootstrap_path))
    else:
        print("not using setpriority", file=sys.stderr)
        thread = local_thread
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
        await proc.check()
        await fd.lseek(0, SEEK.SET)
        raw_data = await thread.read_to_eof(fd)
        return raw_data.decode()
    async def run_many(mode: str, mmaps: int) -> float:
        print("run_many", mode, mmaps, file=sys.stderr)
        times = []
        for _ in range(args.num_runs):
            data = await run_bench(mode, mmaps)
            time = float(data)*1000*1000
            times.append(time)
        return(statistics.mean(times))
    async def get_data(mode: str) -> t.List[t.Tuple[int, int]]:
        return [(i, await run_many(mode, 10**i)) for i in range(1)]
    json.dump({mode: await get_data(mode) for mode in ["subprocess", "rsyscall", "nest"]}, sys.stdout)


if __name__ == "__main__":
    trio.run(main)

