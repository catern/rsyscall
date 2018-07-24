from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import ProcessContext, SubprocessContext, gather_local_bootstrap, wrap_stdin_out_err
from rsyscall.io import Epoller, allocate_epoll, AsyncFileDescriptor
from rsyscall.epoll import EpollEvent, EpollEventMask
import socket
import struct
import time
import unittest
import supervise_api as supervise
import trio
import trio.hazmat
import rsyscall.io
import os
import logging
import signal

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

    def test_epoll_read(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                with self.assertRaises(OSError):
                    await self.task.syscall.read(epoll.number, 4096)
        trio.run(test)

    async def do_async_things(self, epoller, task: rsyscall.io.Task) -> None:
        async with (await rsyscall.io.allocate_pipe(task)) as pipe:
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
                await self.do_async_things(epoller, self.task)
        trio.run(test)

    def test_async_multi(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with trio.open_nursery() as nursery:
                    for i in range(5):
                        nursery.start_soon(self.do_async_things, epoller, self.task)
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
        trio.run(test)

    def test_bind(self) -> None:
        async def test() -> None:
            env = await rsyscall.io.build_unix_environment(self.bootstrap)
            async with rsyscall.io.mkdtemp(env.tmpdir, env.utilities.rm) as (dirfd, path):
                sockfd = await rsyscall.io.allocate_unix_socket(self.task, socket.SOCK_STREAM)
                async with sockfd:
                    await (path/"sock").bind(sockfd)
        trio.run(test)

    def test_listen(self) -> None:
        async def test() -> None:
            env = await rsyscall.io.build_unix_environment(self.bootstrap)
            async with rsyscall.io.mkdtemp(env.tmpdir, env.utilities.rm) as (dirfd, path):
                sockfd = await rsyscall.io.allocate_unix_socket(self.task, socket.SOCK_STREAM)
                # TODO next we need to support asynchronous connect
                # and accept
                # those will be on the epollfd I guess
                # TODO okay we have it, now we need to test it
                async with sockfd:
                    addr = (path/"sock").unix_address()
                    await sockfd.bind(addr)
                    await sockfd.listen(10)
                    clientfd = await rsyscall.io.allocate_unix_socket(self.task, socket.SOCK_STREAM)
                    async with clientfd:
                        await clientfd.connect(addr)
                        connfd, client_addr = await sockfd.accept(0) # type: ignore
                        async with connfd:
                            print(addr, client_addr)
        trio.run(test)

    def test_listen_async(self) -> None:
        async def test() -> None:
            env = await rsyscall.io.build_unix_environment(self.bootstrap)
            async with rsyscall.io.mkdtemp(env.tmpdir, env.utilities.rm) as (dirfd, path):
                async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                    epoller = Epoller(epoll)
                    sockfd = await rsyscall.io.allocate_unix_socket(
                        self.task, socket.SOCK_STREAM)
                    async with sockfd:
                        addr = (path/"sock").unix_address()
                        await sockfd.bind(addr)
                        await sockfd.listen(10)
                        async_sockfd = await AsyncFileDescriptor.make(epoller, sockfd)
                        async with async_sockfd:
                            clientfd = await rsyscall.io.allocate_unix_socket(
                                self.task, socket.SOCK_STREAM)
                            async_clientfd = await AsyncFileDescriptor.make(epoller, clientfd)
                            async with async_clientfd:
                                await async_clientfd.connect(addr)
                                connfd, client_addr = await async_sockfd.accept(0) # type: ignore
                                async with connfd:
                                    print(addr, client_addr)
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

    def test_mmap(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_memory(self.task)) as mapping:
                msg = b"hello"
                await mapping.write(mapping.address, msg)
                self.assertEqual(await mapping.read(mapping.address, len(msg)), msg)
        trio.run(test)

    def test_mmap_clone(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with (await rsyscall.io.ChildTaskMonitor.make(self.task, epoller)) as monitor:
                    thread_maker = rsyscall.io.ThreadMaker(monitor)
                    async with (await rsyscall.io.RsyscallTask.make(self.task, thread_maker, epoller)) as rsyscall_task:
                        async with (await rsyscall.io.allocate_epoll(rsyscall_task.task)) as epoll:
                            epoller2 = Epoller(epoll)
                            # okay, important:
                            # clearly we need to clean up the syscall interface after an exec
                            # or otherwise close it
                            # or whatever
                            # like, otherwise the interface is still open!
                            # maybe we could have the task be an interface,
                            # but I think just closing the syscall interface
                            # would go a long way.
                            # like, closing the syscall interface on a threaded rsyscall,
                            # should probably result in killing and waiting the thread!
                            # or this is really, the ability to close a SI early,
                            # after an exec or exit or whatever.
                            # the other end will be closed too - or may be closed, anyway
                            # but we have to close our end.
                            # (and indeed sometimes their end too, in the threaded case)
                            # and this is what closing a task does I guess
                            # or execing it or whatever
                            # the contextmanager for a task, calls exit in it!
                            # and then after exiting it, closes the SI.

                            # is that the right order? should we have the task itself do some cleanup?
                            # having the task itself do cleanup seems dangerous.
                            # merely exiting should do all the cleanup.

                            # also, we need to figure out how to prevent non-leaf tasks from closing

                            # but, anyway!
                            # so, all I need to do is return a task!
                            # and the task has ownership of the SyscallInterface inside of it.
                            # and I just contextmanager on the task
                            await self.do_async_things(epoller2, rsyscall_task.task)
        trio.run(test)

    def test_thread(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with (await rsyscall.io.ChildTaskMonitor.make(self.task, epoller)) as monitor:
                    thread_maker = rsyscall.io.ThreadMaker(monitor)
                    async with (await rsyscall.io.RsyscallTask.make(self.task, thread_maker, epoller)) as rsyscall_task:
                        # TODO argh! need to PDEATHSIG to kill the threads
                        # TODO argh! this is breaking, for some reason running in the main thread??
                        print(rsyscall_task.task, self.task)
                        print(rsyscall_task.task.syscall, self.task.syscall)
                        print(rsyscall_task.task.syscall._do_syscall, self.task.syscall._do_syscall)
                        # ha ha doesn't return
                        await rsyscall_task.task.syscall.exit2(0)
        trio.run(test)

    def test_do_cloexec(self) -> None:
        pipe = trio.run(rsyscall.io.allocate_pipe, self.task)
        lib.rsyscall_do_cloexec()
        with self.assertRaises(OSError):
            # it was closed due to being cloexec
            trio.run(pipe.wfd.write, b"foo")

if __name__ == '__main__':
    import unittest
    unittest.main()


