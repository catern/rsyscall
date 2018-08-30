from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import gather_local_bootstrap, wrap_stdin_out_err
from rsyscall.io import Epoller, AsyncFileDescriptor
from rsyscall.epoll import EpollEvent, EpollEventMask
import rsyscall.base as base
import rsyscall.memory_abstracted_syscalls as memsys
import socket
import struct
import time
import unittest
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
            async with (await self.task.pipe()) as pipe:
                in_data = b"hello"
                await pipe.wfd.write(in_data)
                out_data = await pipe.rfd.read(len(in_data))
                self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_cat(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await self.task.pipe()) as pipe_in:
                    async with (await self.task.pipe()) as pipe_out:
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
                async with (await self.task.pipe()) as pipe_in:
                    async with (await self.task.pipe()) as pipe_out:
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
        async with (await self.task.pipe()) as pipe:
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
            async with (await self.task.epoll_create()) as epoll:
                epoller = Epoller(epoll)
                await self.do_epoll_things(epoller)
        trio.run(test)

    def test_epoll_multi(self) -> None:
        async def test() -> None:
            async with (await self.task.epoll_create()) as epoll:
                epoller = Epoller(epoll)
                async with trio.open_nursery() as nursery:
                    for i in range(5):
                        nursery.start_soon(self.do_epoll_things, epoller)
        trio.run(test)

    def test_epoll_read(self) -> None:
        async def test() -> None:
            async with (await self.task.epoll_create()) as epoll:
                with self.assertRaises(OSError):
                    await self.task.syscall.read(epoll.number, 4096)
        trio.run(test)

    async def do_async_things(self, epoller, task: rsyscall.io.Task) -> None:
        async with (await task.pipe()) as pipe:
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
            async with (await self.task.epoll_create()) as epoll:
                epoller = Epoller(epoll)
                await self.do_async_things(epoller, self.task)
        trio.run(test)

    def test_async_multi(self) -> None:
        async def test() -> None:
            async with (await self.task.epoll_create()) as epoll:
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
                    async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
                        addr = (path/"sock").unix_address(stdtask.task)
                        await sockfd.bind(addr)
        trio.run(test)

    def test_listen(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as path:
                    async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
                        addr = (path/"sock").unix_address(stdtask.task)
                        await sockfd.bind(addr)
                        await sockfd.listen(10)
                        async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as clientfd:
                            await clientfd.connect(addr)
                            connfd, client_addr = await sockfd.accept(0) # type: ignore
                            async with connfd:
                                print(addr, client_addr)
        trio.run(test)

    def test_listen_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                async with (await stdtask.mkdtemp()) as path:
                    async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
                        addr = (path/"sock").unix_address(stdtask.task)
                        await sockfd.bind(addr)
                        await sockfd.listen(10)
                        async with (await AsyncFileDescriptor.make(stdtask.resources.epoller, sockfd)) as async_sockfd:
                            clientfd = await stdtask.task.socket_unix(socket.SOCK_STREAM)
                            async_clientfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, clientfd)
                            async with async_clientfd:
                                await async_clientfd.connect(addr)
                                connfd, client_addr = await async_sockfd.accept(0) # type: ignore
                                async with connfd:
                                    print(addr, client_addr)
        trio.run(test)

    def test_ip_listen_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                 async with (await stdtask.task.socket_inet(socket.SOCK_STREAM)) as sockfd:
                     bind_addr = sockfd.file.address_type(0, 0x7F_00_00_01)
                     await sockfd.bind(bind_addr)
                     addr = await sockfd.getsockname()
                     await sockfd.listen(10)
                     async with (await AsyncFileDescriptor.make(stdtask.resources.epoller, sockfd)) as async_sockfd:
                         clientfd = await stdtask.task.socket_inet(socket.SOCK_STREAM)
                         async_clientfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, clientfd)
                         async with async_clientfd:
                             await async_clientfd.connect(addr)
                             connfd, client_addr = await async_sockfd.accept(0) # type: ignore
                             async with connfd:
                                 print(addr, client_addr)
        trio.run(test)

    def test_ip_dgram_connect(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                 async with (await stdtask.task.socket_inet(socket.SOCK_DGRAM)) as recv_sockfd:
                     await recv_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
                     addr_recv = await recv_sockfd.getsockname()
                     async with (await stdtask.task.socket_inet(socket.SOCK_DGRAM)) as send1_sockfd:
                         await send1_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
                         addr_send1 = await send1_sockfd.getsockname()
                         await recv_sockfd.connect(addr_send1)
                         await send1_sockfd.connect(addr_recv)
                         async with (await stdtask.task.socket_inet(socket.SOCK_DGRAM)) as send2_sockfd:
                             await send2_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
                             await send2_sockfd.connect(addr_recv)
                             addr_send2 = await send1_sockfd.getsockname()
                             # send some data from send1 and receive it
                             await send1_sockfd.write(b"hello")
                             self.assertEqual(await recv_sockfd.read(4096), b"hello")
                             await send2_sockfd.write(b"goodbye")
                             await send1_sockfd.write(b"hello")
                             self.assertEqual(await recv_sockfd.read(4096), b"hello")
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
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task as stdtask2:
                    await stdtask2.exit(0)
        trio.run(test)

    def test_thread_epoll(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task as stdtask2:
                        await self.do_async_things(stdtask2.resources.epoller, stdtask2.task)
        trio.run(test)

    def test_thread_nest(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task as stdtask2:
                    rsyscall_task3, _ = await stdtask2.spawn([])
                    async with rsyscall_task3 as stdtask3:
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

    def test_do_cloexec_except(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task as stdtask2:
                    pipe = await stdtask2.task.pipe()
                    fds = [stdtask2.task.syscall.infd, stdtask2.task.syscall.outfd] # type: ignore
                    await rsyscall.io.do_cloexec_except(stdtask2.task, fds)
                    with self.assertRaises(OSError):
                        # it was closed due to being cloexec
                        await pipe.wfd.write(b"foo")
        trio.run(test)

    async def do_epoll_things(self, epoller) -> None:
        async with (await self.task.pipe()) as pipe:
            pipe_rfd_wrapped = await epoller.add(pipe.rfd, EpollEventMask.make(in_=True))
            async def stuff():
                events = await pipe_rfd_wrapped.wait()
                self.assertEqual(len(events), 1)
                self.assertTrue(events[0].in_)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(stuff)
                await trio.sleep(0)
                await pipe.wfd.write(b"data")

    def test_epoll_two(self) -> None:
        async def test() -> None:
            async with (await self.task.epoll_create()) as epoll1:
                epoller1 = Epoller(epoll1)
                async with (await self.task.pipe()) as pipe1:
                    pipe1_rfd_wrapped = await epoller1.register(pipe1.rfd, EpollEventMask.make(in_=True))
                    async with (await self.task.epoll_create()) as epoll2:
                        epoller2 = Epoller(epoll2)
                        async with (await self.task.pipe()) as pipe2:
                            pipe2_rfd_wrapped = await epoller2.register(pipe2.rfd, EpollEventMask.make(in_=True))
                            async def stuff(pipe_rfd):
                                events = await pipe_rfd.wait()
                                self.assertEqual(len(events), 1)
                                self.assertTrue(events[0].in_)
                            async with trio.open_nursery() as nursery:
                                nursery.start_soon(stuff, pipe1_rfd_wrapped)
                                nursery.start_soon(stuff, pipe2_rfd_wrapped)
                                await trio.sleep(0)
                                await pipe1.wfd.write(b"data")
                                await pipe2.wfd.write(b"data")
        trio.run(test)

    # first, let's have them both be externally driven, I suppose
    # no wait, what are we going to do testwise?
    # so we have them each registered as epoll on the other one.
    # we'll call wait on the pipe_rfd on both of them.
    # then we'll activate some... stuff...
    # how do we call wait on the pipe_rfd on both of them, if wait blocks??
    # we can't, I guess.
    # before blocking, I guess we need to ensure that no other tasks are ready to run.
    # that's tricky, so let's go with external blocking for now.
    # okay so this is hard, very hard, we will probably not be able to run things until everything is blocked, so...
    # so...
    # how exactly do we ensure that everything that can run, has run?
    # well it's a matter of doing all pending work that we control
    # and only then blocking
    # blocking surrenders control back elsewhere...
    # but if we run a function for someone else...
    # and they call back into us...
    # well actually that only will happen if we have a level-triggered approach.
    # also... don't we need to do something level triggered then?
    # I guess we'll, um...
    # when we do the call into some other guy, they'll do just the, um...
    # just the nonblocking approach.
    # they won't block.
    # we'll block.
    # but no we won't block either.
    # well then when will we block?
    # okay so but yeah.
    # when we do an external blocking for some other guy,
    # that is, internal blocking from our perspective,
    # external blocking for them,
    # then,
    # they need to not block.
    # so yeah...
    # but then alternatively, we can say, let's externalize our blocking to this other guy,
    # and they'll call us when we're good.
    # I mean...
    # proposal is to do blocking internally, when exactly???
    # like, I guess we really do have two modes?
    # one external-blocking always, one internal-blocking always?
    # an internal-blocking guy can monitor for an external-blocking guy...
    # but here's the issue, how can we handle doing internal-blocking in any of our stuff??
    # after all, when we do an internal-block,
    # well, we can't be sure that other events aren't going to appear
    # well, except when we can in fact be sure?????
    # like when we are the only thing in the world,
    # we call our thing,
    # and any new action has to activate us?
    # blaaaaaaaah!
    def test_epoll_coblocking(self) -> None:
        async def test() -> None:
            async with (await self.task.epoll_create()) as epoll1:
                epoller1 = Epoller(epoll1)
                async with (await self.task.pipe()) as pipe1:
                    pipe1_rfd_wrapped = await epoller1.register(pipe1.rfd, EpollEventMask.make(in_=True))
                    async with (await self.task.epoll_create()) as epoll2:
                        epoller2 = Epoller(epoll2)
                        async with (await self.task.pipe()) as pipe2:
                            pipe2_rfd_wrapped = await epoller2.register(pipe2.rfd, EpollEventMask.make(in_=True))
                            async def stuff(pipe_rfd):
                                events = await pipe_rfd.wait()
                                self.assertEqual(len(events), 1)
                                self.assertTrue(events[0].in_)
                            async with trio.open_nursery() as nursery:
                                nursery.start_soon(stuff, pipe1_rfd_wrapped)
                                nursery.start_soon(stuff, pipe2_rfd_wrapped)
                                await trio.sleep(0)
                                await pipe1.wfd.write(b"data")
                                await pipe2.wfd.write(b"data")
        trio.run(test)

if __name__ == '__main__':
    import unittest
    unittest.main()


