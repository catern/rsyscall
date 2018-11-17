import rsyscall.base as base
from rsyscall.io import RsyscallThread
import typing as t

class SSHExecutable:
    def __init__(self, executable_path: base.Path) -> None:
        self.executable_path = executable_path

    # hmm we actually need an rsyscallthread to properly exec
    # would be nice to call this just "Thread".
    # we should namespace the current "Thread" properly, so we can do that...
    async def exec(self, thread: RsyscallThread, config: t.Dict[str, str]) -> None:
        option_list: str = []
        for key, value in config.items():
            option_list += ["-o", f"{key}={value}"]
        child = thread.execve(self.executable_path, ["ssh", "-F", "/dev/null", *option_list])

async def exec_ssh
