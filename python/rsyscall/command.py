import typing as t
from rsyscall.handle import Path
import os

T_command = t.TypeVar('T_command', bound="Command")
class Command:
    def __init__(self,
                 executable_path: Path,
                 arguments: t.List[t.Union[str, bytes, os.PathLike]],
                 env_updates: t.Mapping[str, t.Union[str, bytes, os.PathLike]]) -> None:
        self.executable_path = executable_path
        self.arguments = arguments
        self.env_updates = env_updates

    def args(self: T_command, *args: t.Union[str, bytes, os.PathLike]) -> T_command:
        return type(self)(self.executable_path,
                          [*self.arguments, *args],
                          self.env_updates)

    def env(self: T_command, env_updates: t.Mapping[str, t.Union[str, bytes, os.PathLike]]={},
            **updates: t.Union[str, bytes, os.PathLike]) -> T_command:
        return type(self)(self.executable_path,
                          self.arguments,
                          {**self.env_updates, **env_updates, **updates})

    def in_shell_form(self) -> str:
        ret = ""
        for key, value in self.env_updates.items():
            ret += os.fsdecode(key) + "=" + os.fsdecode(value)
        ret += os.fsdecode(self.executable_path)
        # skip first argument
        for arg in self.arguments[1:]:
            ret += " " + os.fsdecode(arg)
        return ret

    def __str__(self) -> str:
        ret = "Command("
        for key, value in self.env_updates.items():
            ret += f"{key}={value} "
        ret += f"{os.fsdecode(self.executable_path)},"
        for arg in self.arguments:
            ret += " " + os.fsdecode(arg)
        ret += ")"
        return ret