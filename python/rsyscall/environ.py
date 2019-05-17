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

def chunks(l, n):
    # thanks stack overflow
    for i in range(0, len(l), n):
        yield l[i:i+n]

class ExecutablePathCache:
    def __init__(self, task: Task, ram: RAM, paths: t.List[str]) -> None:
        self.task = task
        self.ram = ram
        self.paths = [Path(path) for path in paths]
        self.fds: t.Dict[Path, t.Optional[FileDescriptor]] = {}

    async def lookup_executable_at_path(self, path: Path, name: str) -> None:
        if path in self.fds:
            self.fds
        pass

    async def get_fd_for_path(self, path: Path) -> t.Optional[FileDescriptor]:
        if path not in self.fds:
            try:
                fd = await self.task.open(await self.ram.to_pointer(path), O.PATH|O.DIRECTORY|O.CLOEXEC)
            except OSError:
                self.fds[path] = None
            else:
                self.fds[path] = fd
        return self.fds[path]

    async def check(self, path: Path, name: WrittenPointer[Path]) -> bool:
        fd = await self.get_fd_for_path(path)
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
        nameptr = await self.ram.to_pointer(Path(name))
        # do the lookup for 16 paths at a time, that seems like a good batching number
        for paths in chunks(self.paths, 64):
            thunks = [functools.partial(self.check, path, nameptr) for path in paths]
            results = await run_all(thunks) # type: ignore
            for path, result in zip(paths, results):
                if result:
                    break
            if result:
                break
        else:
            raise Exception("executable not found", name)
        return Command(path/name, [name], {})

class Environment:
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
        result = self.data.get(os.fsencode(key))
        if result is None:
            return default
        else:
            return os.fsdecode(result)

    async def which(self, name: str) -> Command:
        return await self.path.which(name)

    def inherit(self, task: Task, ram: RAM) -> Environment:
        # TODO hmm this is a bit wasteful of the path cache, maybe we should share it?
        # though if we unshare the mount namespace or chroot or chdir, it won't be valid anymore...
        return Environment(task, ram, self.data)
