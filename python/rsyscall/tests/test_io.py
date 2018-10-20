from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import gather_local_bootstrap, wrap_stdin_out_err
from rsyscall.io import AsyncFileDescriptor
from rsyscall.epoll import EpollEvent, EpollEventMask
import rsyscall.base as base
import rsyscall.raw_syscalls as raw_syscall
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
logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)

class TestIO(unittest.TestCase):
    def setUp(self) -> None:
        self.bootstrap = gather_local_bootstrap()
        self.task = self.bootstrap.task
        self.stdstreams = self.bootstrap.stdstreams
        self.stdin = self.stdstreams.stdin
        self.stdout = self.stdstreams.stdout
        self.stderr = self.stdstreams.stderr

    # def test_pipe(self):
    #     async def test() -> None:
    #         async with (await self.task.pipe()) as pipe:
    #             in_data = b"hello"
    #             await pipe.wfd.write(in_data)
    #             out_data = await pipe.rfd.read(len(in_data))
    #             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    # def test_cat(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await self.task.pipe()) as pipe_in:
    #                 async with (await self.task.pipe()) as pipe_out:
    #                     rsyscall_task, (stdin, stdout, new_stdin, new_stdout) = await stdtask.spawn(
    #                         [self.stdin, self.stdout, pipe_in.rfd, pipe_out.wfd])
    #                     async with rsyscall_task:
    #                         await new_stdin.dup2(stdin)
    #                         await new_stdout.dup2(stdout)
    #                         async with (await rsyscall_task.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'cat'])):
    #                             in_data = b"hello"
    #                             await pipe_in.wfd.write(in_data)
    #                             out_data = await pipe_out.rfd.read(len(in_data))
    #                             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    # def test_cat_async(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await self.task.pipe()) as pipe_in:
    #                 async with (await self.task.pipe()) as pipe_out:
    #                     rsyscall_task, (stdin, stdout, new_stdin, new_stdout) = await stdtask.spawn(
    #                         [self.stdin, self.stdout, pipe_in.rfd, pipe_out.wfd])
    #                     async with rsyscall_task:
    #                         await new_stdin.dup2(stdin)
    #                         await new_stdout.dup2(stdout)
    #                         async with (await rsyscall_task.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'cat'])):
    #                             async_cat_rfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, pipe_out.rfd)
    #                             async_cat_wfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, pipe_in.wfd)
    #                             in_data = b"hello world"
    #                             await async_cat_wfd.write(in_data)
    #                             out_data = await async_cat_rfd.read()
    #                             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    # async def do_epoll_things(self, epoller) -> None:
    #     async with (await self.task.pipe()) as pipe:
    #         pipe_rfd_wrapped = await epoller.register(pipe.rfd, EpollEventMask.make(in_=True))
    #         async def stuff():
    #             events = await pipe_rfd_wrapped.wait()
    #             self.assertEqual(len(events), 1)
    #             self.assertTrue(events[0].in_)
    #         async with trio.open_nursery() as nursery:
    #             nursery.start_soon(stuff)
    #             await trio.sleep(0)
    #             await pipe.wfd.write(b"data")

    # def test_epoll(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             await self.do_epoll_things(stdtask.resources.epoller)
    #     trio.run(test)

    # def test_epoll_multi(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             epoller = stdtask.resources.epoller
    #             async with trio.open_nursery() as nursery:
    #                 for i in range(5):
    #                     nursery.start_soon(self.do_epoll_things, epoller)
    #     trio.run(test)

    # def test_epoll_read(self) -> None:
    #     async def test() -> None:
    #         async with (await self.task.epoll_create()) as epoll:
    #             with self.assertRaises(OSError):
    #                 await memsys.read(self.task.syscall, self.task.gateway, self.task.allocator, epoll.pure, 4096)
    #     trio.run(test)

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

    # def test_async(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             epoller = stdtask.resources.epoller
    #             await self.do_async_things(epoller, self.task)
    #     trio.run(test)

    # def test_async_multi(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             epoller = stdtask.resources.epoller
    #             async with trio.open_nursery() as nursery:
    #                 for i in range(5):
    #                     nursery.start_soon(self.do_async_things, epoller, self.task)
    #     trio.run(test)

    # def test_path_cache(self) -> None:
    #     async def test() -> None:
    #         # we need to build a hierarchy of directories
    #         # and create files within them that are executable
    #         # so we need mkdirat, openat
    #         # and an auto-closing temp directory thing
    #         # some kind of recursive removal?
    #         # probably cheaper to exec rm -r so we'll do that instead of implementing walking
    #         # and I guess mkdirat we'll do with Path objects?

    #         # so we'll add a write_text method?
    #         # and we need a tempdir maker thingy
    #         pass
    #     trio.run(test)

    # def test_mkdtemp(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await path.open_directory()) as dirfd:
    #                     self.assertCountEqual([dirent.name for dirent in await dirfd.getdents()], [b'.', b'..'])
    #                     text = b"Hello world!"
    #                     name = b"hello"
    #                     hello_path = await rsyscall.io.spit(path/name, text)
    #                     async with (await hello_path.open(os.O_RDONLY)) as readable:
    #                         self.assertEqual(await readable.read(), text)
    #                     await dirfd.lseek(0, os.SEEK_SET)
    #                     self.assertCountEqual([dirent.name for dirent in await dirfd.getdents()], [b'.', b'..', name])
    #     trio.run(test)

    # def test_bind(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
    #                     addr = (path/"sock").unix_address()
    #                     await sockfd.bind(addr)
    #     trio.run(test)

    # def test_listen(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
    #                     addr = (path/"sock").unix_address()
    #                     await sockfd.bind(addr)
    #                     await sockfd.listen(10)
    #                     async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as clientfd:
    #                         await clientfd.connect(addr)
    #                         connfd, client_addr = await sockfd.accept(0) # type: ignore
    #                         async with connfd:
    #                             logger.info("%s, %s", addr, client_addr)
    #     trio.run(test)

    # def test_listen_async(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
    #                     addr = (path/"sock").unix_address()
    #                     await sockfd.bind(addr)
    #                     await sockfd.listen(10)
    #                     async with (await AsyncFileDescriptor.make(stdtask.resources.epoller, sockfd)) as async_sockfd:
    #                         clientfd = await stdtask.task.socket_unix(socket.SOCK_STREAM)
    #                         async_clientfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, clientfd)
    #                         async with async_clientfd:
    #                             await async_clientfd.connect(addr)
    #                             connfd, client_addr = await async_sockfd.accept(0) # type: ignore
    #                             async with connfd:
    #                                 logger.info("%s, %s", addr, client_addr)
    #     trio.run(test)

    # def test_robust_bind_connect(self) -> None:
    #     "robust_unix_bind and robust_unix_connect work correctly on long Unix socket paths"
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
    #                     sockpath = path/("long"*25 + "sock")
    #                     await rsyscall.io.robust_unix_bind(sockpath, sockfd)
    #                     await sockfd.listen(10)
    #                     async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as clientfd:
    #                         # Unix sockets succeed in connecting immediately, but then block for writing.
    #                         await rsyscall.io.robust_unix_connect(sockpath, clientfd)
    #                         connfd, client_addr = await sockfd.accept(0) # type: ignore
    #                         async with connfd:
    #                             logger.info("Server sockname: %s, client peername: %s, server connection sockname %s",
    #                                         await sockfd.getsockname(),
    #                                         await clientfd.getpeername(),
    #                                         await connfd.getsockname())
    #     trio.run(test)

    # def test_ip_listen_async(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #              async with (await stdtask.task.socket_inet(socket.SOCK_STREAM)) as sockfd:
    #                  bind_addr = sockfd.file.address_type(0, 0x7F_00_00_01)
    #                  await sockfd.bind(bind_addr)
    #                  addr = await sockfd.getsockname()
    #                  await sockfd.listen(10)
    #                  async with (await AsyncFileDescriptor.make(stdtask.resources.epoller, sockfd)) as async_sockfd:
    #                      clientfd = await stdtask.task.socket_inet(socket.SOCK_STREAM)
    #                      async_clientfd = await AsyncFileDescriptor.make(stdtask.resources.epoller, clientfd)
    #                      async with async_clientfd:
    #                          await async_clientfd.connect(addr)
    #                          connfd, client_addr = await async_sockfd.accept(0) # type: ignore
    #                          async with connfd:
    #                              logger.info("%s, %s", addr, client_addr)
    #     trio.run(test)

    # def test_ip_dgram_connect(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #              async with (await stdtask.task.socket_inet(socket.SOCK_DGRAM)) as recv_sockfd:
    #                  await recv_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
    #                  addr_recv = await recv_sockfd.getsockname()
    #                  async with (await stdtask.task.socket_inet(socket.SOCK_DGRAM)) as send1_sockfd:
    #                      await send1_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
    #                      addr_send1 = await send1_sockfd.getsockname()
    #                      await recv_sockfd.connect(addr_send1)
    #                      await send1_sockfd.connect(addr_recv)
    #                      async with (await stdtask.task.socket_inet(socket.SOCK_DGRAM)) as send2_sockfd:
    #                          await send2_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
    #                          await send2_sockfd.connect(addr_recv)
    #                          addr_send2 = await send1_sockfd.getsockname()
    #                          # send some data from send1 and receive it
    #                          await send1_sockfd.write(b"hello")
    #                          self.assertEqual(await recv_sockfd.read(4096), b"hello")
    #                          await send2_sockfd.write(b"goodbye")
    #                          await send1_sockfd.write(b"hello")
    #                          self.assertEqual(await recv_sockfd.read(4096), b"hello")
    #     trio.run(test)

    # def test_getdents_noent(self) -> None:
    #     "getdents on a removed directory throws FileNotFoundError"
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 new_path = await (path/"foo").mkdir()
    #                 async with (await new_path.open_directory()) as new_dirfd:
    #                     await new_path.rmdir()
    #                     with self.assertRaises(FileNotFoundError):
    #                         await new_dirfd.getdents()
    #     trio.run(test)

    # def test_thread_exit(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                 await stdtask2.exit(0)
    #     trio.run(test)

    # def test_thread_epoll(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                     await self.do_async_things(stdtask2.resources.epoller, stdtask2.task)
    #     trio.run(test)

    def test_thread_nest(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                rsyscall_task, _ = await stdtask.spawn([])
                async with rsyscall_task as stdtask2:
                    rsyscall_task3, _ = await stdtask2.spawn([])
                    async with rsyscall_task3 as stdtask3:
                        await self.do_async_things(stdtask3.resources.epoller, stdtask3.task)
        trio.run(test)

    # def test_thread_exec(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task:
    #                 child_task = await rsyscall_task.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'sleep .01'])
    #                 await child_task.wait_for_exit()
    #     trio.run(test)

    # def test_thread_mkdtemp(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             async with (await stdtask.mkdtemp()) as tmpdir:
    #                 pass
    #     trio.run(test)

    # def test_do_cloexec_except(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                 pipe = await stdtask2.task.pipe()
    #                 fds = [stdtask2.task.syscall.infd, stdtask2.task.syscall.outfd] # type: ignore
    #                 await rsyscall.io.do_cloexec_except(stdtask2.task, fds)
    #                 with self.assertRaises(OSError):
    #                     # it was closed due to being cloexec
    #                     await pipe.wfd.write(b"foo")
    #     trio.run(test)

    # def test_epoll_two(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as local_stdtask:
    #             rsyscall_task, _ = await local_stdtask.spawn([])
    #             async with rsyscall_task as stdtask:
    #                 epoller1 = stdtask.resources.epoller
    #                 task = stdtask.task
    #                 async with (await task.pipe()) as pipe1:
    #                     pipe1_rfd_wrapped = await epoller1.register(pipe1.rfd, EpollEventMask.make(in_=True))
    #                     async with (await task.make_epoller()) as epoller2:
    #                         async with (await task.pipe()) as pipe2:
    #                             pipe2_rfd_wrapped = await epoller2.register(pipe2.rfd, EpollEventMask.make(in_=True))
    #                             async def stuff(pipe_rfd):
    #                                 events = await pipe_rfd.wait()
    #                                 self.assertEqual(len(events), 1)
    #                                 self.assertTrue(events[0].in_)
    #                             async with trio.open_nursery() as nursery:
    #                                 nursery.start_soon(stuff, pipe1_rfd_wrapped)
    #                                 nursery.start_soon(stuff, pipe2_rfd_wrapped)
    #                                 await trio.sleep(0)
    #                                 await pipe1.wfd.write(b"data")
    #                                 await pipe2.wfd.write(b"data")
    #     trio.run(test)

    # def test_unshared_thread_epoll(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                     await self.do_async_things(stdtask2.resources.epoller, stdtask2.task)
    #     trio.run(test)

    # def test_unshared_thread_nest(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                 rsyscall_task3, _ = await stdtask2.spawn([])
    #                 async with rsyscall_task3 as stdtask3:
    #                     await self.do_async_things(stdtask3.resources.epoller, stdtask3.task)
    #     trio.run(test)

    # def test_unshared_thread_pipe(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                 async with (await stdtask2.task.pipe()) as pipe:
    #                     in_data = b"hello"
    #                     await pipe.wfd.write(in_data)
    #                     out_data = await pipe.rfd.read(len(in_data))
    #                     logger.info("HELLO")
    #                     self.assertEqual(in_data, out_data)
    #                     logger.info("HELLO 2")
    #                     # so closing is hanging.
    #                     # hmm
    #                     # we sigkill the process...
    #                     # then we try to read from something?
    #                     # logger.info("sleeping %s", rsyscall_task.thread.thread.child_task.process)
    #                     logger.info("sleeping %s", rsyscall_task.child_task.process)
    #                     # await trio.sleep(30923023940)
    #                 logger.info("finished destructing pipe")
    #             logger.info("finished destructing inner task")
    #         logger.info("finished destructing outer task")
    #     trio.run(test)

    # def test_subprocess_pipe(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                 # need to exec into a task
    #                 async with (await stdtask2.task.pipe()) as pipe:
    #                     in_data = b"hello"
    #                     await pipe.wfd.write(in_data)
    #                     out_data = await pipe.rfd.read(len(in_data))
    #                     logger.info("HELLO")
    #                     self.assertEqual(in_data, out_data)
    #                     logger.info("HELLO 2")
    #                     # so closing is hanging.
    #                     # hmm
    #                     # we sigkill the process...
    #                     # then we try to read from something?
    #                     logger.info("sleeping %s", rsyscall_task.child_task.process)
    #                     # await trio.sleep(30923023940)
    #                 logger.info("finished destructing pipe")
    #             logger.info("finished destructing inner task")
    #         logger.info("finished destructing outer task")
    #     trio.run(test)

    # def test_pass_fd(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #             in_data = b"hello"
    #             await l.write(in_data)
    #             out_data = await r.read(len(in_data))
    #             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    # def test_socketpair(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #             in_data = b"hello"
    #             await l.write(in_data)
    #             out_data = await r.read(len(in_data))
    #             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    def test_pass_fd(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                task = stdtask.task
                l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
                await memsys.sendmsg_fds(task.base, task.gateway, task.allocator,
                                         l.active.far, [l.active.far])
                fds = await memsys.recvmsg_fds(task.base, task.gateway, task.allocator,
                                               r.active.far, 1)
                print(fds)
        trio.run(test)

    def test_pass_fd_thread(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as stdtask:
                task = stdtask.task
                l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
                rsyscall_task, [r_remote] = await stdtask.spawn([r.active.far])
                async with rsyscall_task as stdtask2:
                    l2, r2 = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
                    await memsys.sendmsg_fds(task.base, task.gateway, task.allocator,
                                             l.active.far, [r2.active.far])
                    [r2_remote] = await memsys.recvmsg_fds(
                        stdtask2.task.base, stdtask2.task.gateway, stdtask2.task.allocator, r_remote, 1)
                    await r2.aclose()
                    in_data = b"hello"
                    await l2.write(in_data)
                    out_data = await memsys.read(stdtask2.task.syscall,
                                                 stdtask2.task.gateway, stdtask2.task.allocator,
                                                 r2_remote, (len(in_data)))
                    self.assertEqual(in_data, out_data)
                    
                    print(r2_remote)
        trio.run(test)

if __name__ == '__main__':
    import unittest
    unittest.main()


