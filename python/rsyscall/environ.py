"""Functions and classes relating to Unix environment variables.

This is always available to us, and we can use it to look up executables in our
environment and access various other resources.

This will be superseded in many situations, though; for example, if we have
access to a Nix store, we do not need to look at the environment to find
executables.

"""
from __future__ import annotations
from dneio import run_all
from rsyscall.command import Command
from rsyscall.handle import Task, FileDescriptor, WrittenPointer
from rsyscall.handle.pointer import share_pointers
from rsyscall.path import Path
from rsyscall.unistd import ArgList
import os
import typing as t
import functools

from rsyscall.fcntl import O
from rsyscall.unistd import OK
__all__ = [
    'ExecutableNotFound',
    'Environment',
]

T = t.TypeVar('T')
def chunks(lst: t.List[T], size: int) -> t.Iterator[t.List[T]]:
    """Yield chunks of `lst`, at most `size` long.

    Thanks Stack Overflow

    """
    for i in range(0, len(lst), size):
        yield lst[i:i+size]

class ExecutableNotFound(Exception):
    "No executable with this name can be found; thrown from `Environment.which`"
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name

class ExecutablePathCache:
    "A cache of executables looked up on PATH."
    def __init__(self, task: Task, paths: t.Sequence[str | Path]) -> None:
        self.task = task
        self.paths = [Path(path) for path in paths]
        self.fds: t.Dict[Path, t.Optional[FileDescriptor]] = {}
        self.path_cache: t.Dict[str, Path] = {}

    async def _get_fd_for_path(self, path: Path) -> t.Optional[FileDescriptor]:
        "Return a cached file descriptor for this path."
        if path not in self.fds:
            try:
                fd = await self.task.open(await self.task.ptr(path), O.PATH|O.DIRECTORY)
            except OSError:
                self.fds[path] = None
            else:
                self.fds[path] = fd
        return self.fds[path]

    async def _check(self, path: Path, name: WrittenPointer[str]) -> bool:
        "Return true if there's an executable with this name under this path"
        fd = await self._get_fd_for_path(path)
        if fd is None:
            return False
        else:
            try:
                # TODO hmm this returns fine for directories tho. hm. hm.
                # oh well we'll just fail at exec time, that was always possible
                await fd.faccessat(name, OK.X)
            except OSError:
                return False
            else:
                return True

    async def which(self, name: str) -> Command:
        "Locate an executable with this name on PATH; throw ExecutableNotFound on failure"
        try:
            path = self.path_cache[name]
        except KeyError:
            nameptr = await self.task.ptr(name)
            # do the lookup for 64 paths at a time, that seems like a good batching number
            for paths in chunks(self.paths, 64):
                results = await run_all(*[self._check(path, nameptr) for path in paths])
                for path, result in zip(paths, results):
                    if result:
                        # path is set as the loop variable; python has no scope
                        # so we can just break out and use it.
                        break
                if result:
                    break
            else:
                raise ExecutableNotFound(name)
            self.path_cache[name] = path
        return Command(path/name, [name], {})

__pdoc__ = {
    'Environment.__getitem__': True,
    'Environment.__contains__': True,
    'Environment.__len__': True,
    'Environment.__delitem__': True,
    'Environment.__setitem__': True,
}
class Environment:
    "A representation of Unix environment variables."
    @staticmethod
    def make_from_environ(task: Task, environment: t.Dict[str, str]) -> Environment:
        return Environment(task, environment, ExecutablePathCache(task, environment.get("PATH", "").split(":")))

    def __init__(self,
                 task: Task,
                 environment: t.Dict[str, str], path: ExecutablePathCache,
                 arglist_ptr: t.Optional[WrittenPointer[ArgList]]=None,
    ) -> None:
        self.task = task
        self.data = environment
        self.sh = Command(Path("/bin/sh"), ['sh'], {})
        "The POSIX-required `/bin/sh`, as a `rsyscall.Command`"
        self.tmpdir = Path(self.get("TMPDIR", "/tmp"))
        "`TMPDIR`, or `/tmp` if it's not set, as a `rsyscall.path.Path`"
        self.path = path
        self.arglist_ptr = arglist_ptr

    def __getitem__(self, key: str) -> str:
        return self.data[key]

    def __contains__(self, key: str) -> bool:
        return key in self.data

    def __len__(self) -> int:
        return len(self.data)

    def __delitem__(self, key: str) -> None:
        del self.data[key]

    def __setitem__(self, key: str, val: str) -> None:
        self.data[key] = val

    def get(self, key: str, default: str) -> str:
        "Like `dict.get`; get an environment variable, with a default."
        result = self.data.get(key)
        if result is None:
            return default
        else:
            return result

    async def which(self, name: str) -> Command:
        "Locate an executable with this name on `PATH`; throw `ExecutableNotFound` on failure."
        if self.task.mountns is not self.path.task.mountns:
            # this inherited ExecutablePathCache is not in the same mountns as us anymore,
            # start doing path lookups ourselves
            self.path = ExecutablePathCache(self.task, self.path.paths)
        return await self.path.which(name)

    def inherit(self, task: Task) -> Environment:
        """Return a new Environment instance for this Task

        We share the existing ExecutablePathCache. This centralizes path lookups so that
        they're shared between all `rsyscall.thread`es.

        """
        return Environment(task, dict(self.data), self.path, self.arglist_ptr)

    async def as_arglist(self, task: Task) -> WrittenPointer[ArgList]:
        if self.arglist_ptr is None:
            envp = ['='.join([key, value]) for key, value in self.data.items()]
            envp_ptrs = [await task.ptr(arg) for arg in envp]
            ptr = await task.ptr(ArgList(envp_ptrs))
            ptr, *envp_ptrs = await share_pointers([ptr, *envp_ptrs])
            # we could just do two calls to share_pointers (one before task.ptr), but that adds a little latency,
            # so instead we do this horrible abstraction-break
            # TODO think about how to do this safely and abstractly
            ptr.value = ArgList(envp_ptrs)
            self.arglist_ptr = ptr
        return self.arglist_ptr
