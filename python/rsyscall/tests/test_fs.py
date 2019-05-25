from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
import rsyscall.tasks.local as local

from rsyscall.handle import Pointer
from rsyscall.tests.utils import do_async_things
from rsyscall.fcntl import O
from rsyscall.unistd import SEEK
from rsyscall.path import EmptyPath, Path
from rsyscall.linux.dirent import *
from rsyscall.environ import ExecutablePathCache, ExecutableNotFound

class TestFS(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.store = local_store
        self.tmpdir = await self.thr.mkdtemp()
        self.path = self.tmpdir.path

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_copy(self) -> None:
        source_file = await self.thr.task.open(await self.thr.ram.ptr(self.path/"source"), O.RDWR|O.CREAT)
        data = b'hello world'
        buf: Pointer[bytes] = await self.thr.ram.ptr(data)
        valid, rest = await source_file.write(buf)
        buf = valid + rest
        await source_file.lseek(0, SEEK.SET)
        dest_file = await self.thr.task.open(await self.thr.ram.ptr(self.path/"dest"), O.RDWR|O.CREAT)

        thread = await self.thr.fork()
        cat = await self.thr.environ.which("cat")
        await thread.unshare_files_and_replace({
            thread.stdin: source_file,
            thread.stdout: dest_file,
        })
        child_process = await thread.exec(cat)
        await child_process.check()

        await dest_file.lseek(0, SEEK.SET)
        self.assertEqual(await (await dest_file.read(buf))[0].read(), data)

    async def test_getdents(self) -> None:
        dirfd = await self.thr.task.open(await self.thr.ram.ptr(self.path), O.DIRECTORY)
        dent_buf = await self.thr.ram.malloc(DirentList, 4096)
        valid, rest = await dirfd.getdents(dent_buf)
        self.assertCountEqual([dirent.name for dirent in await valid.read()], ['.', '..'])
        dent_buf = valid + rest

        text = b"Hello world!"
        name = await self.thr.ram.ptr(Path("hello"))

        write_fd = await dirfd.openat(name, O.WRONLY|O.CREAT)
        buf = await self.thr.ram.ptr(text)
        written, _ = await write_fd.write(buf)

        read_fd = await dirfd.openat(name, O.RDONLY)
        read, _ = await read_fd.read(written)
        self.assertEqual(await read.read(), text)

        await dirfd.lseek(0, SEEK.SET)
        valid, rest = await dirfd.getdents(dent_buf)
        self.assertCountEqual([dirent.name for dirent in await valid.read()], ['.', '..', str(name.value)])

    async def test_getdents_noent(self) -> None:
        "getdents on a removed directory returns ENOENT/FileNotFoundError"
        name = await self.thr.ram.ptr(self.path/"foo")
        await self.thr.task.mkdir(name)
        dirfd = await self.thr.task.open(name, O.DIRECTORY)
        await self.thr.task.rmdir(name)
        buf = await self.thr.ram.malloc(DirentList, 4096)
        with self.assertRaises(FileNotFoundError):
            await dirfd.getdents(buf)

    async def test_readlinkat_non_symlink(self) -> None:
        f = await self.thr.task.open(await self.thr.ram.ptr(Path(".")), O.PATH)
        empty_ptr = await self.thr.ram.ptr(EmptyPath())
        ptr = await self.thr.ram.malloc(Path, 4096)
        with self.assertRaises(FileNotFoundError):
            await f.readlinkat(empty_ptr, ptr)

    async def test_readlink_proc(self) -> None:
        f = await self.thr.task.open(await self.thr.ram.ptr(Path(".")), O.PATH)
        path_ptr = await self.thr.ram.ptr(f.as_proc_self_path())
        ptr = await self.thr.ram.malloc(Path, 4096)
        await f.readlinkat(path_ptr, ptr)

    async def test_which(self) -> None:
        names = []
        for i in range(5):
            name = await self.thr.ram.ptr(self.path/f"dir{i}")
            names.append(name)
            await self.thr.task.mkdir(name)
        cache = ExecutablePathCache(self.thr.task, self.thr.ram, [str(name.value) for name in names])

        with self.assertRaises(ExecutableNotFound):
            await cache.which("foo")
        with self.assertRaises(ExecutableNotFound):
            await cache.which("foo")
        fd = await self.thr.task.open(await self.thr.ram.ptr(names[2].value/"foo"), O.CREAT)
        await fd.fchmod(0o700)
        await cache.which("foo")
        
