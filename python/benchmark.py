import trio
from rsyscall import Path, Command, Thread
import rsyscall.tasks.local as local
import rsyscall.nix as nix
from rsyscall.tasks.stdin_bootstrap import stdin_bootstrap, stdin_bootstrap_path_from_store
from rsyscall.unistd import SEEK
from rsyscall.sys.resource import PRIO
from statistics import mean
import csv
import argparse
from dataclasses import dataclass

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import typing as t

@dataclass
class Run:
    pid: int
    # all in microseconds
    pre_fork: int
    in_child: int
    in_parent: int
    after_exit: int

usec_in_sec = 1000*1000

def analyze_data(data: str) -> float:
    runs = []
    for line in csv.DictReader(data.split()):
        runs.append(Run(int(line['pid']),
            pre_fork=int(line['pre_fork_sec'])*usec_in_sec + int(line['pre_fork_usec']),
            in_child=int(line['in_child_sec'])*usec_in_sec + int(line['in_child_usec']),
            in_parent=int(line['in_parent_sec'])*usec_in_sec + int(line['in_parent_usec']),
            after_exit=int(line['after_exit_sec'])*usec_in_sec + int(line['after_exit_usec']),
        ))

    return sum(run.after_exit - run.pre_fork for run in runs)/len(runs)

async def main() -> None:
    parser = argparse.ArgumentParser(description='Do benchmarking')
    parser.add_argument('--no-use-setpriority', help="don't setpriority before benchmarking; doing that requires privileges,"
                        " which are attained by running the benchmark with sudo (handled internally)",
                        action='store_true')
    parser.add_argument('executable', type=Path)
    parser.add_argument('num_runs', type=int)
    
    args = parser.parse_args()

    cmd = Command(args.executable, [args.executable], {})

    if not args.no_use_setpriority:
        print("using sudo to use setpriority")
        stdin_bootstrap_path = await stdin_bootstrap_path_from_store(nix.local_store)
        proc, thread = await stdin_bootstrap(
            local.thread, (await local.thread.environ.which("sudo")).args(stdin_bootstrap_path))
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
        proc = await child.exec(cmd.args(mode, str(mmaps)))
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
            time = analyze_data(data)
            times.append(time)
        return(mean(times))
    async def get_data(mode: str) -> t.List[t.Tuple[int, int]]:
        return [(i, await run_many(mode, 10**i)) for i in range(6)]
    # fork = [(0, 76.55446666666667), (1, 77.37133333333334), (2, 82.745), (3, 132.49946666666668), (4, 471.80173333333335), (5, 4062.4732), (6, 42670.6794)]
    # clone = [(0, 18.5436), (1, 20.663266666666665), (2, 18.799533333333333), (3, 19.606266666666667), (4, 20.892733333333332), (5, 20.747866666666667), (6, 21.152866666666668)]
    # clone_fork = [(0, 42.185066666666664), (1, 43.29793333333333), (2, 44.864733333333334), (3, 66.6312), (4, 212.4854), (5, 2751.410533333333), (6, 22280.86373333333)]
    fork = await get_data("fork")
    clone = await get_data("clone")
    clone_fork = await get_data("clone_fork")
    print("fork =", fork)
    print("clone =", clone)
    print("clone_fork =", clone_fork)
    fig, ax = plt.subplots()
    plt.xscale('log')
    plt.yscale('log')
    ax.plot([10**x for x, y in fork], [y for x, y in fork], 'o-', label="fork()")
    ax.plot([10**x for x, y in clone], [y for x, y in clone], '^-', label="clone(CLONE_VM)")
    ax.plot([10**x for x, y in clone_fork], [y for x, y in clone_fork], 'x-', label="clone()")
    ax.legend()
    
    ax.set(xlabel='Pages mapped in memory', ylabel='time (us)')
    ax.grid()
    
    fig.savefig("microbench.png")
    plt.show()

# def analyze_data(data: str) -> float:
#     runs = []
#     for line in csv.DictReader(data.split()):
#         runs.append(Run(int(line['pid']),
#             pre_fork=int(line['pre_fork_sec'])*usec_in_sec + int(line['pre_fork_usec']),
#             in_child=int(line['in_child_sec'])*usec_in_sec + int(line['in_child_usec']),
#             in_parent=int(line['in_parent_sec'])*usec_in_sec + int(line['in_parent_usec']),
#             after_exit=int(line['after_exit_sec'])*usec_in_sec + int(line['after_exit_usec']),
#         ))

#     return sum(run.after_exit - run.pre_fork for run in runs)/len(runs)

if __name__ == "__main__":
    # print(analyze_data(open('data').read()))
    trio.run(main)
