from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import gather_local_bootstrap, wrap_stdin_out_err
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

    def test_cat(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_in:
                    async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_out:
                        rsyscall_task, (stdin, stdout, new_stdin, new_stdout) = await stdtask.spawn(
                            [self.stdin, self.stdout, pipe_in.rfd, pipe_out.wfd])
                        async with rsyscall_task:
                            await new_stdin.dup2(stdin)
                            await new_stdout.dup2(stdout)
                            child_task = await rsyscall_task.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'cat'])
                            in_data = b"hello"
                            await pipe_in.wfd.write(in_data)
                            out_data = await pipe_out.rfd.read(len(in_data))
                            self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_cat_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_in:
                    async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_out:
                        rsyscall_task, (stdin, stdout, new_stdin, new_stdout) = await stdtask.spawn(
                            [self.stdin, self.stdout, pipe_in.rfd, pipe_out.wfd])
                        async with rsyscall_task:
                            await new_stdin.dup2(stdin)
                            await new_stdout.dup2(stdout)
                            child_task = await rsyscall_task.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'cat'])
                            async_cat_rfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, pipe_out.rfd)
                            async_cat_wfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, pipe_in.wfd)
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
                await trio.sleep(0.01)
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

    def test_mkdtemp(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as path:
                    async with (await path.open_directory()) as dirfd:
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
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as path:
                    async with (await rsyscall.io.allocate_unix_socket(stdtask.task, socket.SOCK_STREAM)) as sockfd:
                        addr = (path/"sock").unix_address(stdtask.task)
                        await sockfd.bind(addr)
        trio.run(test)

    def test_listen(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as path:
                    async with (await rsyscall.io.allocate_unix_socket(stdtask.task, socket.SOCK_STREAM)) as sockfd:
                        addr = (path/"sock").unix_address(stdtask.task)
                        await sockfd.bind(addr)
                        await sockfd.listen(10)
                        async with (await rsyscall.io.allocate_unix_socket(stdtask.task, socket.SOCK_STREAM)) as clientfd:
                            await clientfd.connect(addr)
                            connfd, client_addr = await sockfd.accept(0) # type: ignore
                            async with connfd:
                                print(addr, client_addr)
        trio.run(test)

    def test_listen_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as path:
                    async with (await rsyscall.io.allocate_unix_socket(stdtask.task, socket.SOCK_STREAM)) as sockfd:
                        addr = (path/"sock").unix_address(stdtask.task)
                        await sockfd.bind(addr)
                        await sockfd.listen(10)
                        async with (await AsyncFileDescriptor.make(stdtask.resources.epoller, sockfd)) as async_sockfd:
                            clientfd = await rsyscall.io.allocate_unix_socket(stdtask.task, socket.SOCK_STREAM)
                            async_clientfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, clientfd)
                            async with async_clientfd:
                                # doop doop doop hmm
                                # it would be nice if, actually, we had UnixAddress be a Union[UnixAddress, Path]
                                # all Paths are valid UnixAddresses,
                                # but not all UnixAddresses are valid Paths
                                # hm.
                                await async_clientfd.connect(addr)
                                connfd, client_addr = await async_sockfd.accept(0) # type: ignore
                                async with connfd:
                                    print(addr, client_addr)
        trio.run(test)

    def test_getdents_noent(self) -> None:
        "getdents on a removed directory throws FileNotFoundError"
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as path:
                    new_path = await (path/"foo").mkdir()
                    async with (await new_path.open_directory()) as new_dirfd:
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

    def test_thread_exit(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with (await rsyscall.io.ChildTaskMonitor.make(self.task, epoller)) as monitor:
                    thread_maker = rsyscall.io.ThreadMaker(monitor)
                    rsyscall_spawner = rsyscall.io.RsyscallSpawner(self.task, thread_maker, epoller)
                    rsyscall_task, _ = await rsyscall_spawner.spawn([])
                    async with rsyscall_task:
                        await rsyscall_task.exit(0)
        trio.run(test)

    def test_thread_epoll(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task:
                    async with (await rsyscall.io.allocate_epoll(rsyscall_task.task)) as epoll:
                        epoller2 = Epoller(epoll)
                        await self.do_async_things(epoller2, rsyscall_task.task)
        trio.run(test)

    def test_thread_nest(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task:
                    # TODO figure out how to inherit this properly
                    # only then can I set env variables
                    # I should maybe store env variables in StdTask?
                    # then use StdTask for exec?
                    # clearly I need to use stdtask for exec, yes
                    # and have spawn return another stdtask I guess
                    # though then I need to resolve the rsyscall task resources problem...
                    # I can go with closing a task
                    # and that closes the SI
                    # which closes the RscConn
                    # which somehow affects the CThread?!??!??!
                    # oh, but we clearly need to also have the CThread when we exec,
                    # so we can extract the Child from it.
                    # so we can combine the task and rsyscallconnection,
                    # and just close the task.
                    # but we still need to handle the thread
                    stdtask2 = rsyscall.io.StandardTask(
                        rsyscall_task.task,
                        await rsyscall.io.TaskResources.make(rsyscall_task.task),
                        stdtask.process, stdtask.filesystem)
                    rsyscall_task3, _ = await stdtask2.spawn([])
                    async with rsyscall_task3:
                        stdtask3 = rsyscall.io.StandardTask(
                            rsyscall_task3.task,
                            await rsyscall.io.TaskResources.make(rsyscall_task3.task),
                            stdtask.process, stdtask.filesystem)
                        await self.do_async_things(stdtask3.resources.epoller, stdtask3.task)
        trio.run(test)

    def test_thread_exec(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task:
                    child_task = await rsyscall_task.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'sleep .01'])
                    await child_task.wait_for_exit()
        trio.run(test)

    def test_thread_mkdtemp(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as tmpdir:
                    pass
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


