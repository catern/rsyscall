from __future__ import annotations
import rsyscall.base as base
from rsyscall.io import RsyscallThread, ChildTask
import typing as t

@dataclass
class Command:
    executable_path: base.Path
    arguments: t.List[str]
    env_updates: t.Dict[str, str]

    @classmethod
    def make(cls, executable_path: base.Path, argv0: str) -> Command:
        return cls(executable_path, [argv0], {})

    def add_args(self, args: t.List[str]) -> Command:
        return type(self)(self.executable_path,
                             self.arguments + args,
                             self.env_updates)

    def update_env(self, env_updates: t.Dict[str, str]) -> Command:
        return type(self)(self.executable_path,
                             self.arguments,
                             {**self.env_updates, **env_updates})

    def __str__(self) -> str:
        ret = ""
        for key, value in self.env_updates.items():
            ret += f"{key}={value} "
        ret += str(executable_path)
        for arg in self.arguments:
            ret += f" {arg}"

    # hmm we actually need an rsyscallthread to properly exec
    # would be nice to call this just "Thread".
    # we should namespace the current "Thread" properly, so we can do that...
    async def exec(self, thread: RsyscallThread) -> ChildTask:
        return (await thread.execve(self.executable_path, self.arguments, self.env_updates))

class SSHCommand(Command):
    def add_ssh_options(self, config: t.Dict[str, str]) -> SSHCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", f"{key}={value}"]
        return self.add_args(option_list)

    def add_proxy_command(self, command: Command) -> SSHCommand:
        return self.add_ssh_options({'ProxyCommand': str(command)})

    @classmethod
    def make(cls, executable_path: base.Path) -> SSHCommand:
        return super().make(executable_path, "ssh")

class SSHDCommand(Command):
    def add_sshd_options(self, config: t.Dict[str, str]) -> SSHDCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", f"{key}={value}"]
        return self.add_args(option_list)

    @classmethod
    def make(cls, executable_path: base.Path) -> SSHDCommand:
        return super().make(executable_path, "sshd")
