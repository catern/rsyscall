from dataclasses import dataclass
import csv
import sys

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

def main() -> None:
    analyze_data(sys.stdin.read())

if __name__ == "__main__":
    main()
