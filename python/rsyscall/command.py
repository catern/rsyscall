"Provides the Command class, which is a convenient representation of the arguments to execve."
import typing as t
from rsyscall.path import Path
import os

T_command = t.TypeVar('T_command', bound="Command")
class Command:
    "A convenient builder-pattern representation of the arguments to execve."
    def __init__(self,
                 executable_path: t.Union[str, os.PathLike],
                 arguments: t.List[t.Union[str, os.PathLike]],
                 env_updates: t.Mapping[str, t.Union[str, os.PathLike]]) -> None:
        self.executable_path = executable_path
        self.arguments = arguments
        self.env_updates = env_updates

    def args(self: T_command, *args: t.Union[str, os.PathLike]) -> T_command:
        "Add more arguments to this Command."
        return type(self)(self.executable_path,
                          [*self.arguments, *args],
                          self.env_updates)

    def env(self: T_command, env_updates: t.Mapping[str, t.Union[str, os.PathLike]]={},
            **updates: t.Union[str, os.PathLike]) -> T_command:
        """Add more environment variable updates to this Command.

        There are two ways to pass arguments to this method (which can be used simultaneously):
        - you can pass a dictionary of environment updates,
        - or you can provide your environment updates as keyword arguments.
        Both are necessary, since there are many valid environment variable
        names which are not valid Python keyword argument names.

        """
        return type(self)(self.executable_path,
                          self.arguments,
                          {**self.env_updates, **env_updates, **updates})

    def in_shell_form(self) -> str:
        "Render this Command as a string which could be passed to a shell."
        ret = ""
        for key, value in self.env_updates.items():
            ret += os.fsdecode(key) + "=" + os.fsdecode(value) + " "
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

    def __repr__(self) -> str:
        return str(self)
