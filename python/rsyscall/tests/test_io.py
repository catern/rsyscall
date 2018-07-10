from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import ProcessContext, SubprocessContext, gather_local_bootstrap, wrap_stdin_out_err
from rsyscall.io import Epoller, allocate_epoll, AsyncFileDescriptor
from rsyscall.epoll import EpollEvent, EpollEventMask
import unittest
import supervise_api as supervise
import trio
import trio.hazmat
import rsyscall.io
import os
import logging

logging.basicConfig(level=logging.DEBUG)

class TestIO(unittest.TestCase):
    def setUp(self):
        self.bootstrap = gather_local_bootstrap()
        self.task = self.bootstrap.task
        self.stdstreams = self.bootstrap.stdstreams
        self.stdin = self.stdstreams.stdin
        self.stdout = self.stdstreams.stdout
        self.stderr = self.stdstreams.stderr

    def test_pipe(self):
        async def test() -> None:
            async with (await rsyscall.io.allocate_pipe(self.task)) as pipe:
                in_data = b"hello"
                await pipe.wfd.write(in_data)
                out_data = await pipe.rfd.read(len(in_data))
                self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_subprocess(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.task) as subproc:
                await subproc.exit(0)
        trio.run(test)

    def test_subprocess_fcntl(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.task) as subproc:
                await subproc.exit(0)
        trio.run(test)

    def test_subprocess_nested(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.task):
                async with rsyscall.io.subprocess(self.task) as subproc:
                    await subproc.exit(0)
        trio.run(test)

    def test_cat(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_in:
                async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_out:
                    async with rsyscall.io.subprocess(self.task) as subproc:
                        await subproc.translate(pipe_in.rfd).dup2(subproc.translate(self.stdin))
                        await subproc.translate(pipe_out.wfd).dup2(subproc.translate(self.stdout))
                        await subproc.exec("/bin/sh", ['sh', '-c', 'cat'])
                    in_data = b"hello"
                    await pipe_in.wfd.write(in_data)
                    out_data = await pipe_out.rfd.read(len(in_data))
                    self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_cat_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_in:
                    async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_out:
                        async with rsyscall.io.subprocess(self.task) as subproc:
                            await subproc.translate(pipe_in.rfd).dup2(subproc.translate(self.stdin))
                            await subproc.translate(pipe_out.wfd).dup2(subproc.translate(self.stdout))
                            await subproc.exec("/bin/sh", ['sh', '-c', 'cat'])
                        async_cat_rfd = await AsyncFileDescriptor.make(epoller, pipe_out.rfd)
                        async_cat_wfd = await AsyncFileDescriptor.make(epoller, pipe_in.wfd)
                        in_data = b"hello world"
                        await async_cat_wfd.write(in_data)
                        out_data = await async_cat_rfd.read()
                        self.assertEqual(in_data, out_data)
        trio.run(test)

    async def do_epoll_things(self, epoller) -> None:
        async with (await rsyscall.io.allocate_pipe(self.task)) as pipe:
            pipe_rfd_wrapped = await epoller.add(pipe.rfd, EpollEventMask.make(in_=True))
            async def stuff():
                events = await pipe_rfd_wrapped.wait()
                self.assertEqual(len(events), 1)
                self.assertTrue(events[0].in_)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(stuff)
                await trio.sleep(0)
                await pipe.wfd.write(b"data")

    def test_epoll(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                await self.do_epoll_things(epoller)
        trio.run(test)

    def test_epoll_multi(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with trio.open_nursery() as nursery:
                    for i in range(5):
                        nursery.start_soon(self.do_epoll_things, epoller)
        trio.run(test)

    async def do_async_things(self, epoller) -> None:
        async with (await rsyscall.io.allocate_pipe(self.task)) as pipe:
            async_pipe_rfd = await AsyncFileDescriptor.make(epoller, pipe.rfd)
            async_pipe_wfd = await AsyncFileDescriptor.make(epoller, pipe.wfd)
            data = b"hello world"
            async def stuff():
                result = await async_pipe_rfd.read()
                self.assertEqual(result, data)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(stuff)
                await trio.sleep(0)
                await async_pipe_wfd.write(data)

    def test_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                await self.do_async_things(epoller)
        trio.run(test)

    def test_async_multi(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with trio.open_nursery() as nursery:
                    for i in range(5):
                        nursery.start_soon(self.do_async_things, epoller)
        trio.run(test)

    def test_clonefd(self) -> None:
        async def test() -> None:
            async with rsyscall.io.clonefd(self.task, self.stdstreams) as subproc:
                await subproc.exec("/bin/sh", ['-c', 'sleep inf'])
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                process = await subproc.raw_proc.make_async(epoller)
                await process.terminate()
                with self.assertRaises(supervise.UncleanExit):
                    await process.check()
                await process.close()
        trio.run(test)

    def test_path_cache(self) -> None:
        async def test() -> None:
            # we need to build a hierarchy of directories
            # and create files within them that are executable
            # so we need mkdirat, openat
            # and an auto-closing temp directory thing
            # some kind of recursive removal?
            # probably cheaper to exec rm -r so we'll do that instead of implementing walking
            # and I guess mkdirat we'll do with Path objects?

            # so we'll add a write_text method?
            # and we need a tempdir maker thingy
            pass
        trio.run(test)

    def test_unix_environment(self) -> None:
        async def test() -> None:
            env = await rsyscall.io.build_unix_environment(self.bootstrap)
        trio.run(test)

    def test_mkdtemp(self) -> None:
        async def test() -> None:
            env = await rsyscall.io.build_unix_environment(self.bootstrap)
            async with rsyscall.io.mkdtemp(env.tmpdir, env.utilities.rm) as (dirfd, path):
                self.assertCountEqual([dirent.name for dirent in await dirfd.getdents()], [b'.', b'..'])
                text = b"Hello world!"
                name = b"hello"
                hello_path = await rsyscall.io.spit(path/name, text)
                async with (await hello_path.open(os.O_RDONLY)) as readable:
                    self.assertEqual(await readable.read(), text)
                await dirfd.lseek(0, os.SEEK_SET)
                self.assertCountEqual([dirent.name for dirent in await dirfd.getdents()], [b'.', b'..', name])

                new_path = await (path/"foo").mkdir()
                async with (await new_path.open(os.O_DIRECTORY)) as new_dirfd:
                    await new_path.rmdir()
                    print(await new_dirfd.getdents())
        trio.run(test)

    def test_getdents_noent(self) -> None:
        "getdents on a removed directory throws FileNotFoundError"
        async def test() -> None:
            env = await rsyscall.io.build_unix_environment(self.bootstrap)
            async with rsyscall.io.mkdtemp(env.tmpdir, env.utilities.rm) as (dirfd, path):
                new_path = await (path/"foo").mkdir()
                async with (await new_path.open(os.O_DIRECTORY)) as new_dirfd:
                    await new_path.rmdir()
                    with self.assertRaises(FileNotFoundError):
                        await new_dirfd.getdents()
        trio.run(test)

if __name__ == '__main__':
    import unittest
    unittest.main()


