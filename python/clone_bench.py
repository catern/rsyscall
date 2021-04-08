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

async def run_benchmark(run_mode: str, thing_mode: str) -> int:
    cmd = await local.thread.environ.which('true')
    await local.thread.environ.as_arglist(local.thread.ram)
    if run_mode == 'stdlib':
        if thing_mode == 'spawn':
            async def run() -> None:
                popen = subprocess.Popen([cmd.executable_path], preexec_fn=lambda: None)
                popen.wait()
        elif thing_mode in ['spawn_newns', 'spawn_newpid', 'spawn_newnspid']:
            async def run() -> None:
                pass
        elif thing_mode == 'getpid':
            async def run() -> None:
                # hmm we want to bypass the pid cache.
                os.getpgid(0)
    else:
        if run_mode == 'rsyscall':
            thread = local.thread
        elif run_mode == 'nest':
            thread = await local.thread.clone()
        elif run_mode == 'nestnest':
            first_nesting_child = await local.thread.clone()
            thread = await first_nesting_child.clone()
        elif run_mode == 'flags':
            thread = await local.thread.clone(CLONE.NEWNS|CLONE.NEWPID)
        if thing_mode == 'getpid':
            async def run() -> None:
                await thread.task.getpgid()
        else:
            if thing_mode == 'spawn':
                flags = CLONE.NONE
            elif thing_mode == 'spawn_newns':
                flags = CLONE.NEWNS
            elif thing_mode == 'spawn_newpid':
                flags = CLONE.NEWPID
            elif thing_mode == 'spawn_newnspid':
                flags = CLONE.NEWNS|CLONE.NEWPID
            async def run() -> None:
                child = await thread.clone(flags)
                child_proc = await child.execv(cmd.executable_path, [cmd.executable_path])
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
    run_modes = ['rsyscall', 'nest', 'nestnest', 'flags']
    parser.add_argument('--run-mode', choices=run_modes)
    thing_modes = ['spawn', 'spawn_newns', 'spawn_newpid', 'spawn_newnspid']
    parser.add_argument('--thing-mode', choices=thing_modes)
    parser.add_argument('--no-use-setpriority', help="don't setpriority before benchmarking; doing that requires privileges,"
                        " which are attained by running the benchmark with sudo (handled internally)",
                        action='store_true')
    parser.add_argument('num_runs', type=int)

    args = parser.parse_args()

    if args.run_mode:
        print(await run_benchmark(args.run_mode, args.thing_mode))
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
    async def run_bench(run_mode: str, thing_mode: str) -> int:
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
            '--run-mode', run_mode,
            '--thing-mode', thing_mode, '0'))
        await child.close()
        await proc.check()
        await fd.lseek(0, SEEK.SET)
        raw_data = await thread.read_to_eof(fd)
        return raw_data.decode()
    async def run_many(run_mode: str, thing_mode: str) -> float:
        times = []
        for _ in range(args.num_runs):
            data = await run_bench(run_mode, thing_mode)
            time = float(data)*1000*1000
            times.append(time)
        return(mean(times))
    raw_data = {}
    # for i in range(args.num_runs):
    #     print("run", i)
    #     for run_mode in run_modes:
    #         for thing_mode in thing_modes:
    #             result = await run_bench(run_mode, thing_mode)
    #             time = float(result)*1000*1000
    #             raw_data.setdefault(run_mode, dict()).setdefault(thing_mode, list()).append(time)
    # data = {run_mode: {thing_mode: mean(values) for thing_mode, values in thing_values.items()}
    #         for run_mode, thing_values in raw_data.items()}
    data = {'rsyscall': {'spawn': 2143.242041269938, 'spawn_newns': 12769.540945688883, 'spawn_newpid': 5203.498045603435, 'spawn_newnspid': 16132.054646809896}, 'nest': {'spawn': 5643.887122472127, 'spawn_newns': 15543.795108795166, 'spawn_newpid': 8705.60614267985, 'spawn_newnspid': 19266.490300496418}, 'nestnest': {'spawn': 5649.184544881185, 'spawn_newns': 15834.43284034729, 'spawn_newpid': 8707.117160161337, 'spawn_newnspid': 19424.70908164978}, 'flags': {'spawn': 7850.373109181722, 'spawn_newns': 18372.32240041097, 'spawn_newpid': 13005.960702896118, 'spawn_newnspid': 23936.61292394002}}
    print("data =", data)
    def line(row: t.List) -> str:
        return " & ".join(str(x) for x in row) + " \\\\"
    print('\\begin{tabular}{r|' + ''.join('r' for _ in thing_modes) + '}')
    print('\\hline')
    print(line(['', *[name.replace('_', '\\_') for name in thing_modes]]))
    print('\\hline')
    for name, row in data.items():
        print(line([name, *[round(x, 1) for x in row.values()]]))
    print('\\hline')
    print('\\end{tabular}')

    # maybe let's not compare against stdlib?
    # yeah since most of these can't be done by subprocess.spawn, and we've already established our slowdown,
    # we don't include a comparison against stdlib
    labels = ['spawn', 'spawn_newpid', 'spawn_newns', 'spawn_newnspid']

    
    x = np.arange(len(labels))  # the label locations
    width = 0.22  # the width of the bars
    all_rects = []

    fig, ax = plt.subplots()
    positions = x - 1.5*width
    print(positions)
    for run_mode in run_modes:
        rects = ax.bar(positions, [round(data[run_mode][thing]/1000, 1) for thing in labels], width,
                       label={
                           'rsyscall':'local',
                           'nest':'clone()',
                           'nestnest':'clone().clone()',
                           'flags':'clone(NS|PID)',
                       }[run_mode])
        all_rects.append(rects)
        positions += width
    
    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Milliseconds to create child')
    # ax.set_title('Time to create different processes, by variety of parent process')
    ax.set_xlabel('Child process')
    ax.set_xticks(x)
    ax.set_xticklabels([{
        'spawn':'clone()',
        'spawn_newns':'clone(NS)',
        'spawn_newpid':'clone(PID)',
        'spawn_newnspid':'clone(NS|PID)',
    }[label] for label in labels])
    ax.legend(title="Parent process")
    
    # hmm. comparison with getpid is tricky.
    # we should just say in prose how getpid performs.
    # after all, there's no difference between nest, nestnest, or flags.
    
    def autolabel(rect, xoff=0):
        height = rect.get_height()
        ax.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(xoff, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    autolabel(all_rects[0][0])
    autolabel(all_rects[1][0])
    autolabel(all_rects[2][0])
    autolabel(all_rects[3][0])
    autolabel(all_rects[0][1])
    autolabel(all_rects[1][1])
    autolabel(all_rects[2][1])
    autolabel(all_rects[3][1])
    autolabel(all_rects[0][2], -1)
    autolabel(all_rects[1][2], -1)
    autolabel(all_rects[2][2], -1)
    autolabel(all_rects[3][2])
    autolabel(all_rects[0][3], -1)
    autolabel(all_rects[1][3], -1)
    autolabel(all_rects[2][3], -1)
    autolabel(all_rects[3][3])
    
    fig.tight_layout()
    
    fig.savefig("clone_bench.png")
    plt.show()

if __name__ == "__main__":
    trio.run(main)

