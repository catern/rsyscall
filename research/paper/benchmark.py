import trio
from rsyscall import Path, Command
import rsyscall.tasks.local as local
import rsyscall.nix as nix
from rsyscall.tasks.stdin_bootstrap import stdin_bootstrap, stdin_bootstrap_path_from_store
from rsyscall.unistd import SEEK
import csv
import argparse
from dataclasses import dataclass

@dataclass
class Run:
    pid: int
    # all in microseconds
    pre_fork: int
    in_child: int
    in_parent: int
    after_exit: int

usec_in_sec = 1000*1000

def analyze_data(data: str) -> None:
    runs = []
    for line in csv.DictReader(data.split()):
        runs.append(Run(int(line['pid']),
            pre_fork=int(line['pre_fork_sec'])*usec_in_sec + int(line['pre_fork_usec']),
            in_child=int(line['in_child_sec'])*usec_in_sec + int(line['in_child_usec']),
            in_parent=int(line['in_parent_sec'])*usec_in_sec + int(line['in_parent_usec']),
            after_exit=int(line['after_exit_sec'])*usec_in_sec + int(line['after_exit_usec']),
        ))

    print(sum(run.after_exit - run.pre_fork for run in runs)/len(runs))

async def main() -> None:
    parser = argparse.ArgumentParser(description='Do benchmarking')
    parser.add_argument('executable', type=Path)
    parser.add_argument('num_runs', type=int)
    
    args = parser.parse_args()

    cmd = Command(args.executable, [args.executable, "100"], {})

    # ugh I need nicing
    # let's do that privileged exec thing?
    # then we'll need to support nicing things, too. but fine, this is good.
    # we can hopefully get this done tonight.
    # ugh uUGHHG ugh ugh.
    # ok so sudo doesn't let you inherit higher file descriptors, because it sucks and is bad. hm.
    # but, we could just do this all on the sudo side. nice, good hack!
    stdin_bootstrap_path = await stdin_bootstrap_path_from_store(nix.local_store)
    proc, privthread = await stdin_bootstrap(
        local.thread, (await local.thread.environ.which("sudo")).args(stdin_bootstrap_path))
    fd = await privthread.task.memfd_create(await privthread.ptr(Path("data")))
    print("hi 0")
    child = await privthread.clone()
    print("hi 1")
    await child.inherit_fd(fd).dup2(child.stdout)
    print("hi 2")
    await (await child.exec(cmd)).check()
    print("hi 3")
    await fd.lseek(0, SEEK.SET)
    print("hi 4")
    raw_data = await privthread.read_to_eof(fd)
    print("hi 5")

    analyze_data(raw_data.decode())


if __name__ == "__main__":
    # analyze_data(open('data').read())
    trio.run(main)
