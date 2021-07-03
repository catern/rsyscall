from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread

from rsyscall import Pointer
from rsyscall.path import Path
from rsyscall.tests.utils import do_async_things
from rsyscall.fcntl import O, AT
from rsyscall.unistd import SEEK
from rsyscall.sched import CLONE
from rsyscall.stdlib import mkdtemp
from rsyscall.linux.dirent import *
from rsyscall.environ import ExecutablePathCache, ExecutableNotFound

class TestFS(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread
        self.tmpdir = await mkdtemp(self.thr)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_copy(self) -> None:
        source_file = await self.thr.task.open(await self.thr.ram.ptr(self.tmpdir/"source"), O.RDWR|O.CREAT)
        data = b'hello world'
        buf: Pointer[bytes] = await self.thr.ram.ptr(data)
        valid, rest = await source_file.write(buf)
        buf = valid + rest
        await source_file.lseek(0, SEEK.SET)
        dest_file = await self.thr.task.open(await self.thr.ram.ptr(self.tmpdir/"dest"), O.RDWR|O.CREAT)

        thread = await self.thr.clone()
        cat = await self.thr.environ.which("cat")
        await thread.task.inherit_fd(source_file).dup2(thread.stdin)
        await thread.task.inherit_fd(dest_file).dup2(thread.stdout)
        child_process = await thread.exec(cat)
        await child_process.check()

        await dest_file.lseek(0, SEEK.SET)
        self.assertEqual(await (await dest_file.read(buf))[0].read(), data)

    async def test_getdents(self) -> None:
        dirfd = await self.thr.task.open(await self.thr.ram.ptr(self.tmpdir), O.DIRECTORY)
        dent_buf = await self.thr.ram.malloc(DirentList, 4096)
        valid, rest = await dirfd.getdents(dent_buf)
        self.assertCountEqual([dirent.name for dirent in await valid.read()], ['.', '..'])
        dent_buf = valid + rest

        text = b"Hello world!"
        name = await self.thr.ram.ptr("hello")

        write_fd = await dirfd.openat(name, O.WRONLY|O.CREAT)
        buf = await self.thr.ram.ptr(text)
        written, _ = await write_fd.write(buf)

        read_fd = await dirfd.openat(name, O.RDONLY)
        read, _ = await read_fd.read(written)
        self.assertEqual(await read.read(), text)

        await dirfd.lseek(0, SEEK.SET)
        valid, rest = await dirfd.getdents(dent_buf)
        self.assertCountEqual([dirent.name for dirent in await valid.read()], ['.', '..', name.value])

    async def test_getdents_noent(self) -> None:
        "getdents on a removed directory returns ENOENT/FileNotFoundError"
        name = await self.thr.ram.ptr(self.tmpdir/"foo")
        await self.thr.task.mkdir(name)
        dirfd = await self.thr.task.open(name, O.DIRECTORY)
        await self.thr.task.rmdir(name)
        buf = await self.thr.ram.malloc(DirentList, 4096)
        with self.assertRaises(FileNotFoundError):
            await dirfd.getdents(buf)

    async def test_readlinkat_non_symlink(self) -> None:
        f = await self.thr.task.open(await self.thr.ptr("."), O.PATH)
        empty_ptr = await self.thr.ram.ptr("")
        ptr = await self.thr.ram.malloc(str, 4096)
        with self.assertRaises(FileNotFoundError):
            await f.readlinkat(empty_ptr, ptr)

    async def test_fdat(self) -> None:
        "The *at system calls on FileDescriptor work"
        root = await self.thr.task.open(await self.thr.ptr(self.tmpdir), O.DIRECTORY)
        name = await self.thr.ptr("foo")
        await root.mkdirat(name)
        await root.rmdirat(name)
        file = await root.openat(await self.thr.ptr("."), O.TMPFILE|O.WRONLY)
        await self.thr.task.linkat(None, await self.thr.ptr(file.as_proc_path()), root, name, AT.SYMLINK_FOLLOW)
        await root.renameat(name, root, name)
        await root.unlinkat(name)
        await root.symlinkat(name, name)

    async def test_readlink_proc(self) -> None:
        f = await self.thr.task.open(await self.thr.ptr("."), O.PATH)
        path_ptr = await self.thr.ram.ptr(f"/proc/self/fd/{int(f)}")
        ptr = await self.thr.ram.malloc(str, 4096)
        await f.readlinkat(path_ptr, ptr)

    async def test_which(self) -> None:
        names = []
        for i in range(5):
            name = await self.thr.ram.ptr(self.tmpdir/f"dir{i}")
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
        
