from __future__ import annotations
import rsyscall.base as base
from rsyscall.io import RsyscallThread, ChildTask
from dataclasses import dataclass
import typing as t

T = t.TypeVar('T')
@dataclass
class Command:
    executable_path: base.Path
    arguments: t.List[str]
    env_updates: t.Mapping[str, str]

    @classmethod
    def make(cls, executable_path: base.Path, argv0: str) -> Command:
        return cls(executable_path, [argv0], {})

    def args(self: T, args: t.List[str]) -> T:
        return type(self)(self.executable_path,
                             self.arguments + args,
                             self.env_updates)

    def env(self: T, env_updates: t.Mapping[str, str]) -> T:
        return type(self)(self.executable_path,
                             self.arguments,
                             {**self.env_updates, **env_updates})

    def __str__(self) -> str:
        ret = ""
        for key, value in self.env_updates.items():
            ret += f"{key}={value} "
        ret += str(self.executable_path)
        # skip first argument
        for arg in self.arguments[1:]:
            ret += f" {arg}"
        return ret

    # hmm we actually need an rsyscallthread to properly exec
    # would be nice to call this just "Thread".
    # we should namespace the current "Thread" properly, so we can do that...
    async def exec(self, thread: RsyscallThread) -> ChildTask:
        return (await thread.execve(self.executable_path, self.arguments, self.env_updates))

class SSHCommand(Command):
    def ssh_options(self, config: t.Mapping[str, str]) -> SSHCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", f"{key}={value}"]
        return self.args(option_list)

    def proxy_command(self: T, command: Command) -> T:
        return self.ssh_options({'ProxyCommand': str(command)})

    def local_forward(self: T, local_socket: str, remote_socket: str) -> T:
        return self.args(["-L", f"{local_socket}:{remote_socket}"])

    @classmethod
    def make(cls, executable_path: base.Path) -> SSHCommand:
        return super().make(executable_path, "ssh")

class SSHDCommand(Command):
    def sshd_options(self, config: t.Mapping[str, str]) -> SSHDCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", f"{key}={value}"]
        return self.args(option_list)

    @classmethod
    def make(cls, executable_path: base.Path) -> SSHDCommand:
        return super().make(executable_path, "sshd")
