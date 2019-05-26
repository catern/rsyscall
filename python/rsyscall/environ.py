"""Functions and classes relating to Unix environment variables

This is always available to us, and we can use it to look up executables in our
environment and access various other resources.

This will be superseded in many situations, though; for example, if we have
access to a Nix store, we do not need to look at the environment to find
executables.

"""
from __future__ import annotations
from rsyscall.command import Command
from rsyscall.concurrency import run_all
from rsyscall.handle import Path, Task, FileDescriptor, WrittenPointer
from rsyscall.memory.ram import RAM
import os
import typing as t
import functools

from rsyscall.fcntl import O
from rsyscall.unistd import OK

T = t.TypeVar('T')
def chunks(lst: t.List[T], size: int) -> t.Iterator[t.List[T]]:
    """Yields chunks of `lst`, at most `size` long

    Thanks Stack Overflow

    """
    for i in range(0, len(lst), size):
        yield lst[i:i+size]

class ExecutableNotFound(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name

class ExecutablePathCache:
    "A cache of executables looked up on PATH"
    def __init__(self, task: Task, ram: RAM, paths: t.List[str]) -> None:
        self.task = task
        self.ram = ram
        self.paths = [Path(path) for path in paths]
        self.fds: t.Dict[Path, t.Optional[FileDescriptor]] = {}
        self.name_to_path: t.Dict[str, Path] = {}

    async def _get_fd_for_path(self, path: Path) -> t.Optional[FileDescriptor]:
        "Return a cached file descriptor for this path"
        if path not in self.fds:
            try:
                fd = await self.task.open(await self.ram.ptr(path), O.PATH|O.DIRECTORY)
            except OSError:
                self.fds[path] = None
            else:
                self.fds[path] = fd
        return self.fds[path]

    async def _check(self, path: Path, name: WrittenPointer[Path]) -> bool:
        "Return true if there's an executable with this name under this path"
        fd = await self._get_fd_for_path(path)
        if fd is None:
            return False
        else:
            try:
                # TODO hmm this returns fine for directories tho. hm. hm.
                # oh well we'll just fail at exec time, that was always possible
                await fd.faccessat(name, OK.R|OK.X)
            except OSError:
                return False
            else:
                return True

    async def which(self, name: str) -> Command:
        "Locate an executable with this name on PATH; throw ExecutableNotFound on failure"
        try:
            path = self.name_to_path[name]
        except KeyError:
            nameptr = await self.ram.ptr(Path(name))
            # do the lookup for 64 paths at a time, that seems like a good batching number
            for paths in chunks(self.paths, 64):
                thunks = [functools.partial(self._check, path, nameptr) for path in paths]
                results = await run_all(thunks) # type: ignore
                for path, result in zip(paths, results):
                    if result:
                        # path is set as the loop variable; python has no scope
                        # so we can just break out and use it.
                        break
                if result:
                    break
            else:
                raise ExecutableNotFound(name)
            self.name_to_path[name] = path
        return Command(path/name, [name], {})

class Environment:
    "A representation of Unix environment variables."
    def __init__(self, task: Task, ram: RAM, environment: t.Dict[bytes, bytes]) -> None:
        self.data = environment
        self.sh = Command(Path("/bin/sh"), ['sh'], {})
        self.tmpdir = Path(self.get("TMPDIR", "/tmp"))
        self.path = ExecutablePathCache(task, ram, self.get("PATH", "").split(":"))

    def __getitem__(self, key: t.Union[str, bytes]) -> str:
        return os.fsdecode(self.data[os.fsencode(key)])

    def __contains__(self, key: t.Union[str, bytes]) -> bool:
        return os.fsencode(key) in self.data

    def __len__(self) -> int:
        return len(self.data)

    def __delitem__(self, key: t.Union[str, bytes]) -> None:
        del self.data[os.fsencode(key)]

    def __setitem__(self, key: t.Union[str, bytes], val: t.Union[str, bytes]) -> None:
        self.data[os.fsencode(key)] = os.fsencode(val)

    def get(self, key: t.Union[str, bytes], default: str) -> str:
        "Like dict.get; get an environment variable, with a default."
        result = self.data.get(os.fsencode(key))
        if result is None:
            return default
        else:
            return os.fsdecode(result)

    async def which(self, name: str) -> Command:
        "Locate an executable with this name on PATH; throw ExecutableNotFound on failure"
        return await self.path.which(name)

    def inherit(self, task: Task, ram: RAM) -> Environment:
        # TODO hmm this is a bit wasteful of the path cache, maybe we should share it?
        # though if we unshare the mount namespace or chroot or chdir, it won't be valid anymore...
        return Environment(task, ram, self.data)
