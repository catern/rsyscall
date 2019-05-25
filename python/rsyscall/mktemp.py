"""Making temporary directories
"""
import random
import string
from rsyscall.unix_thread import UnixThread
from rsyscall.memory.ram import RAMThread
from rsyscall.path import Path
from rsyscall.handle import WrittenPointer
import os
import typing as t

def random_string(k=8) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))

async def update_symlink(thr: RAMThread, path: WrittenPointer[Path], target: t.Union[str, Path]) -> WrittenPointer[Path]:
    "Atomically update this path to contain a symlink pointing at this target"
    target_bytes = os.fsencode(target)
    tmpname = path.value.name + ".updating." + random_string(k=8)
    tmppath = await thr.ram.ptr(path.value.parent/tmpname)
    await thr.task.symlink(await thr.ram.ptr(target_bytes), tmppath)
    await thr.task.rename(tmppath, path)
    return path

async def mkdtemp(thr: UnixThread, prefix: str="mkdtemp") -> 'TemporaryDirectory':
    parent = thr.environ.tmpdir
    name = prefix+"."+random_string(k=8)
    await thr.task.mkdir(await thr.ram.ptr(parent/name), 0o700)
    return TemporaryDirectory(thr, parent, name)

class TemporaryDirectory:
    def __init__(self, thr: UnixThread, parent: Path, name: str) -> None:
        self.thr = thr
        self.parent = parent
        self.name = name
        self.path = parent/name

    async def cleanup(self) -> None:
        # TODO would be nice if not sharing the fs information gave us a cap to chdir
        cleanup = await self.thr.fork()
        await cleanup.task.chdir(await cleanup.ram.ptr(self.parent))
        child = await cleanup.exec(self.thr.environ.sh.args(
            '-c', f"chmod -R +w -- {self.name} && rm -rf -- {self.name}"))
        await child.check()

    async def __aenter__(self) -> Path:
        return self.path

    async def __aexit__(self, *args, **kwargs):
        await self.cleanup()
