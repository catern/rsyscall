"Functions for making temporary directories."
import random
import string
from rsyscall.thread import Thread
from rsyscall.path import Path
from rsyscall.handle import WrittenPointer
import os
import typing as t

def random_string(k: int=8) -> str:
    "Return a random string - useful for making files that don't conflict with others."
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))

async def update_symlink(thr: Thread, path: WrittenPointer[Path],
                         target: t.Union[str, os.PathLike]) -> WrittenPointer[Path]:
    "Atomically update this path to contain a symlink pointing at this target."
    tmpname = path.value.name + ".updating." + random_string(k=8)
    tmppath = await thr.ram.ptr(path.value.parent/tmpname)
    await thr.task.symlink(await thr.ram.ptr(target), tmppath)
    await thr.task.rename(tmppath, path)
    return path

async def mkdtemp(thr: Thread, prefix: str="mkdtemp") -> 'TemporaryDirectory':
    "Make a temporary directory in thr.environ.tmpdir."
    parent = thr.environ.tmpdir
    name = prefix+"."+random_string(k=8)
    await thr.task.mkdir(await thr.ram.ptr(parent/name), 0o700)
    return TemporaryDirectory(thr, parent, name)

class TemporaryDirectory(Path):
    "A temporary directory we've created and are responsible for cleaning up."
    def __init__(self, thr: Thread, parent: Path, name: str) -> None:
        "Don't directly instantiate, use rsyscall.mktemp.mkdtemp to create this class."
        self.thr = thr
        super().__init__(parent, name)

    async def cleanup(self) -> None:
        """Delete this temporary directory and everything inside it.

        We do this cleanup by execing sh; that's the cheapest way to do it.  We have to
        chmod -R +w the directory before we rm -rf it, because the directory might contain
        files without the writable bit set, which would prevent us from deleting it.

        """
        # TODO would be nice if not sharing the fs information gave us a cap to chdir
        cleanup = await self.thr.clone()
        await cleanup.task.chdir(await cleanup.ram.ptr(self.parent))
        child = await cleanup.exec(self.thr.environ.sh.args(
            '-c', f"chmod -R +w -- {self.name} && rm -rf -- {self.name}"))
        await child.check()

    async def __aenter__(self) -> Path:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.cleanup()
