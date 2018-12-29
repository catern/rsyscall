import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import wrap_stdin_out_err
from rsyscall.io import AsyncFileDescriptor
from rsyscall.io import local_stdtask, build_local_stdtask, StandardTask
from rsyscall.io import Command
from rsyscall.epoll import EpollEvent, EpollEventMask
from rsyscall.tests.test_ssh import ssh_to_localhost
import shutil
import rsyscall.base as base
import rsyscall.near as near
import rsyscall.far as far
from rsyscall.io import local_stdtask
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory_abstracted_syscalls as memsys
import socket
import struct
import time
import signal
import unittest
import trio
import trio.hazmat
import rsyscall.io
import os
import logging
import signal
logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)

nix_bin_bytes = b"/nix/store/flyhfw91kycrzmlx5v2172b3si4zc0xx-nix-2.2pre6526_9f99d624/bin"

class TestIO(unittest.TestCase):
    def test_pipe(self):
        async def test() -> None:
            async with (await self.task.pipe()) as pipe:
                in_data = b"hello"
                await pipe.wfd.write(in_data)
                out_data = await pipe.rfd.read(len(in_data))
                self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_recv_pipe(self) -> None:
        """Sadly, recv doesn't work on pipes

        Which is a major bummer, because that would allow us to avoid
        messing with O_NONBLOCk stuff

        """
        async def test() -> None:
            async with (await self.task.pipe()) as pipe:
                in_data = b"hello"
                await pipe.wfd.write(in_data)
                out_data = await memsys.recv(self.task.base, self.task.gateway, self.task.allocator,
                                             pipe.rfd.handle.far, len(in_data), 0)
                self.assertEqual(in_data, out_data)
        trio.run(test)

    # def test_cat(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             await self.do_epoll_things(stdtask.resources.epoller)
    #     trio.run(test)

    # def test_epoll_multi(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
                logger.info("performing read")
                result = await async_pipe_rfd.read()
                self.assertEqual(result, data)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(stuff)
                await trio.sleep(0.01)
                logger.info("performing write")
                # hmmm MMM MMMmmmm MMM mmm MMm mm MM mmm MM mm MM
                # does this make sense?
                await async_pipe_wfd.write(data)

    def test_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
                epoller = stdtask.epoller
                await self.do_async_things(epoller, stdtask.task)
        trio.run(test)

    # def test_async_multi(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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

    def test_mkdtemp(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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

    # def test_bind(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
    #                     addr = (path/"sock").unix_address()
    #                     await sockfd.bind(addr)
    #     trio.run(test)

    # def test_listen(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 new_path = await (path/"foo").mkdir()
    #                 async with (await new_path.open_directory()) as new_dirfd:
    #                     await new_path.rmdir()
    #                     with self.assertRaises(FileNotFoundError):
    #                         await new_dirfd.getdents()
    #     trio.run(test)

    # def test_thread_exit(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                 await stdtask2.exit(0)
    #     trio.run(test)

    # def test_thread_epoll(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                     await self.do_async_things(stdtask2.resources.epoller, stdtask2.task)
    #     trio.run(test)

    async def runner(self, test: t.Callable[[StandardTask], t.Awaitable[None]]) -> None:
        async with trio.open_nursery() as nursery:
            stdtask = await build_local_stdtask(nursery)
            await test(stdtask)

    def test_spawn_nest(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread1 = await stdtask.spawn_exec()
            async with thread1 as stdtask2:
                thread2 = await stdtask2.spawn_exec()
                async with thread2 as stdtask3:
                    await self.do_async_things(stdtask3.resources.epoller, stdtask3.task)
        trio.run(self.runner, test)

    def test_thread_nest(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread1 = await stdtask.fork()
            async with thread1 as stdtask2:
                print("ABOUT TO FORK")
                thread2 = await stdtask2.fork()
                print("DONE FORk")
                async with thread2 as stdtask3:
                    await self.do_async_things(stdtask3.epoller, stdtask3.task)
        trio.run(self.runner, test)

    def test_thread_exit(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                await stdtask2.exit(0)
        trio.run(self.runner, test)

    def test_thread_nest_exit(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                print("SBAUGH okay started first task")
                thread3 = await stdtask2.fork()
                print("SBAUGH okay started second task")
                async with thread3 as stdtask3:
                    print("SBAUGH okay with on second task")
                    await stdtask3.exit(0)
                    print("SBAUGH okay exited second task")
        trio.run(self.runner, test)

    def test_thread_unshare(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                await stdtask2.unshare_files()
                thread3 = await stdtask2.fork()
                async with thread3 as stdtask3:
                    print("DOING UNSHARE")
                    await stdtask3.unshare_files()
                    print("UNSHARE DONE")
                    await self.do_async_things(stdtask3.local_epoller, stdtask3.task)
        trio.run(self.runner, test)

    def test_thread_async(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                await self.do_async_things(stdtask2.local_epoller, stdtask2.task)
        trio.run(self.runner, test)

    def test_thread_exec(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                child_task = await thread.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'sleep .01'])
                await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_persistent(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                child_task = await thread.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'sleep .01'])
                await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_thread_signal_queue(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                sigqueue = await rsyscall.io.SignalQueue.make(stdtask2.task, stdtask2.local_epoller, {signal.SIGINT})
                print("epfd", stdtask.epoller.epfd)
                await thread.thread.child_task.send_signal(signal.SIGINT)
                orig_mask = await rsyscall.io.SignalBlock.make(stdtask.task, {signal.SIGINT})
                data = await sigqueue.sigfd.read_nonblock()
                print("read", data)
                data = await sigqueue.sigfd.read_nonblock()
                print("read", data)
                data = await sigqueue.sigfd.read()
        trio.run(self.runner, test)

    def test_ssh_basic(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with ssh_to_localhost(stdtask) as ssh_command:
                local_child, remote_stdtask = await rsyscall.io.spawn_ssh(
                    stdtask, ssh_command)
                logger.info("about to fork")
                remote_thread = await remote_stdtask.fork()
                logger.info("done with fork")
                async with remote_thread:
                    # there's no test on mount namespace at the moment, so it works to pull this from local
                    logger.info("about to exec")
                    child_task = await remote_thread.execve(stdtask.filesystem.utilities.sh, ['sh', '-c', 'sleep .01'])
                    logger.info("done exec, waiting now")
                    await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_ssh_transmit(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with ssh_to_localhost(stdtask) as ssh_command:
                local_child, remote_stdtask = await rsyscall.io.spawn_ssh(
                    stdtask, ssh_command)
                async with (await stdtask.mkdtemp()) as local_tmpdir:
                    async with (await remote_stdtask.mkdtemp()) as remote_tmpdir:
                        [(local_sock, remote_sock)] = await remote_stdtask.make_connections(1)
                        data = b"hello world"
                        await local_sock.write(data)
                        read_data = await remote_stdtask.task.read(remote_sock.far)
                        self.assertEqual(read_data, data)
        trio.run(self.runner, test)

    def test_ssh_copy(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with ssh_to_localhost(stdtask) as ssh_command:
                local_child, remote_stdtask = await rsyscall.io.spawn_ssh(
                    stdtask, ssh_command)
                async with (await stdtask.mkdtemp()) as local_tmpdir:
                    async with (await remote_stdtask.mkdtemp()) as remote_tmpdir:
                        remote_file = await (remote_tmpdir/"dest").open(os.O_RDWR|os.O_CREAT)
                        local_file = await (local_tmpdir/"source").open(os.O_RDWR|os.O_CREAT)
                        data = b'hello world'
                        await local_file.write(data)
                        await local_file.lseek(0, os.SEEK_SET)

                        [(local_sock, remote_sock)] = await remote_stdtask.make_connections(1)
                        print("local_sock remote_sock", local_sock, remote_sock)

                        local_thread = await stdtask.fork()
                        local_cat = await rsyscall.io.which(stdtask, b"cat")
                        local_child_task = await rsyscall.io.exec_cat(
                            local_thread, local_cat, infd=local_file.handle, outfd=local_sock.handle)
                        await local_sock.handle.invalidate()
                        await local_child_task.wait_for_exit()

                        remote_thread = await remote_stdtask.fork()
                        remote_cat = await rsyscall.io.which(remote_stdtask, b"cat")
                        remote_child_task = await rsyscall.io.exec_cat(
                            remote_thread, remote_cat, infd=remote_sock, outfd=remote_file.handle)
                        await remote_sock.invalidate()
                        await remote_child_task.wait_for_exit()

                        await remote_file.lseek(0, os.SEEK_SET)
                        self.assertEqual(await remote_file.read(), data)
        trio.run(self.runner, test)

    def test_ssh_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with ssh_to_localhost(stdtask) as ssh_command:
                local_child, remote_stdtask = await rsyscall.io.spawn_ssh(
                    stdtask, ssh_command)
                async with (await remote_stdtask.mkdtemp()) as remote_tmpdir:
                    thread = await remote_stdtask.fork()
                    bash = await rsyscall.io.which(remote_stdtask, b"bash")
                    await thread.stdtask.task.chdir(remote_tmpdir)
                    await ((await (remote_tmpdir/"var").mkdir())/"stuff").mkdir()
                    child_task = await bash.exec(thread)
                    await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_copy(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp()) as tmpdir:
                source_file = await (tmpdir/"source").open(os.O_RDWR|os.O_CREAT)
                data = b'hello world'
                await source_file.write(data)
                await source_file.lseek(0, os.SEEK_SET)
                dest_file = await (tmpdir/"dest").open(os.O_RDWR|os.O_CREAT)

                thread = await stdtask.fork()
                cat = await rsyscall.io.which(stdtask, b"cat")
                child_task = await rsyscall.io.exec_cat(thread, cat, source_file.handle, dest_file.handle)
                await child_task.wait_for_exit()

                await dest_file.lseek(0, os.SEEK_SET)
                self.assertEqual(await dest_file.read(), data)
        trio.run(self.runner, test)

    def test_ssh_nix_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with ssh_to_localhost(stdtask) as ssh_command:
                local_child, remote_stdtask = await rsyscall.io.spawn_ssh(
                    stdtask, ssh_command)
                thread = await remote_stdtask.fork()
                src_nix_bin = stdtask.task.base.make_path_from_bytes(nix_bin_bytes)
                dest_nix_bin = await rsyscall.io.create_nix_container(src_nix_bin, stdtask, thread.stdtask)
                # let's use nix-copy-closure or nix-store --import/--export or nix copy to copy bash over then run it?
                # nix-store --import/--export
                bash = await rsyscall.io.which(stdtask, b"bash")
                dest_bash = await rsyscall.io.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, thread.stdtask)
                child_task = await thread.execve(dest_bash, ["bash"])
                await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_nix_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            src_nix_bin = stdtask.task.base.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.io.create_nix_container(src_nix_bin, stdtask, thread.stdtask)
            bash = await rsyscall.io.which(stdtask, b"bash")
            dest_bash = await rsyscall.io.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, thread.stdtask)
            child_task = await thread.execve(dest_bash, ["bash", "--norc"])
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_nix_shell_with_daemon(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            src_nix_bin = stdtask.task.base.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.io.create_nix_container(src_nix_bin, stdtask, thread.stdtask)
            child_task = await thread.execve(dest_nix_bin/"nix-daemon", ["nix-daemon"], {'NIX_REMOTE':''})

            shell_thread = await stdtask.fork()
            dest_nix_bin = shell_thread.stdtask.task.base.make_path_handle(dest_nix_bin)
            async with child_task.get_pid() as proc:
                if proc is None:
                    raise Exception("nix daemon died?")
                container_ns_dir = shell_thread.stdtask.task.root()/"proc"/str(proc.near.id)/"ns"
                usernsfd = await (container_ns_dir/"user").open(os.O_RDONLY)
            await shell_thread.stdtask.setns_user(usernsfd.handle)
            await shell_thread.stdtask.unshare_mount()
            await shell_thread.stdtask.task.mount(b"nix", b"/nix", b"none", lib.MS_BIND|lib.MS_RDONLY, b"")
            # making a readonly bind mount is weird, you have to mount it first then remount it rdonly
            await shell_thread.stdtask.task.mount(b"none", b"/nix", b"none",
                                                  lib.MS_BIND|lib.MS_REMOUNT|lib.MS_RDONLY, b"")
            bash = await rsyscall.io.which(stdtask, b"bash")
            dest_bash = await rsyscall.io.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, shell_thread.stdtask)
            mount = await rsyscall.io.which(stdtask, b"mount")
            # don't seem to be able to copy coreutils for some reason?
            # it doesn't have a valid signature?
            await rsyscall.io.nix_deploy(src_nix_bin, mount.executable_path,
                                         stdtask, dest_nix_bin, shell_thread.stdtask)
            child_task = await shell_thread.execve(dest_bash, ["bash", "--norc"])
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

    # def test_thread_mkdtemp(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             async with (await stdtask.mkdtemp()) as tmpdir:
    #                 pass
    #     trio.run(test)

    # def test_do_cloexec_except(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as local_stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                     await self.do_async_things(stdtask2.resources.epoller, stdtask2.task)
    #     trio.run(test)

    # def test_unshared_thread_nest(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             rsyscall_task, _ = await stdtask.spawn([])
    #             async with rsyscall_task as stdtask2:
    #                 rsyscall_task3, _ = await stdtask2.spawn([])
    #                 async with rsyscall_task3 as stdtask3:
    #                     await self.do_async_things(stdtask3.resources.epoller, stdtask3.task)
    #     trio.run(test)

    # def test_unshared_thread_pipe(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #             in_data = b"hello"
    #             await l.write(in_data)
    #             out_data = await r.read(len(in_data))
    #             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    # def test_socketpair(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #             in_data = b"hello"
    #             await l.write(in_data)
    #             out_data = await r.read(len(in_data))
    #             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    def test_pass_fd(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
                task = stdtask.task
                l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
                await memsys.sendmsg_fds(task.base, task.gateway, task.allocator,
                                         l.handle.far, [l.handle.far])
                fds = await memsys.recvmsg_fds(task.base, task.gateway, task.allocator,
                                               r.handle.far, 1)
                print(fds)
        trio.run(test)

    def test_fork_exec(self) -> None:
        async def test() -> None:
            child_thread = await local_stdtask.fork()
            sh = Command(local_stdtask.filesystem.utilities.sh, ['sh'], {})
            child_task = await sh.args(['-c', 'true']).exec(child_thread)
            await child_task.wait_for_exit()
        trio.run(test)

    # def test_pass_fd_thread(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             task = stdtask.task
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #             rsyscall_task, [r_remote] = await stdtask.spawn([r.handle.far])
    #             async with rsyscall_task as stdtask2:
    #                 l2, r2 = await stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    #                 await memsys.sendmsg_fds(task.base, task.gateway, task.allocator,
    #                                          l.handle.far, [r2.handle.far])
    #                 [r2_remote] = await memsys.recvmsg_fds(
    #                     stdtask2.task.base, stdtask2.task.gateway, stdtask2.task.allocator, r_remote, 1)
    #                 await r2.aclose()
    #                 in_data = b"hello"
    #                 await l2.write(in_data)
    #                 out_data = await memsys.read(stdtask2.task.syscall,
    #                                              stdtask2.task.gateway, stdtask2.task.allocator,
    #                                              r2_remote, (len(in_data)))
    #                 self.assertEqual(in_data, out_data)
                    
    #                 print("HELLO", r2_remote)
    #     trio.run(test)

    # def test_socket_binder(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             task = stdtask.task
    #             describe_pipe = await task.pipe()
    #             binder_process, [describe_write] = await stdtask.spawn([describe_pipe.wfd.handle.far])
    #             binder_task = binder_process.stdtask.task.base
    #             if int(describe_write) != 1:
    #                 await near.dup3(binder_task.sysif, binder_task.to_near_fd(describe_write), near.FileDescriptor(1), 0)
    #             async_describe = await AsyncFileDescriptor.make(stdtask.resources.epoller, describe_pipe.rfd)
    #             socket_binder_executable = rsyscall.io.Path.from_bytes(
    #                 binder_process.stdtask.task, shutil.which("rsyscall_server").encode()) # type: ignore
    #             async with binder_process:
    #                 # hmm so we need a proper Thread thingy, so we can exec properly and deal with RsyscallHangup
    #                 child = await binder_process.execve(socket_binder_executable, ["socket_binder"])
    #                 data_path, pass_path = [rsyscall.io.Path.from_bytes(task, data_path) async
    #                                         for line in rsyscall.io.read_lines(async_describe)]
    #                 pass_sock = await task.socket_unix(socket.SOCK_STREAM)
    #                 await rsyscall.io.robust_unix_connect(pass_path, pass_sock)
    #                 listening_sock, = await memsys.recvmsg_fds(task.base, task.gateway, task.allocator,
    #                                                            pass_sock.handle.far, 1)
    #                 (await child.wait_for_exit()).check()
    #             client_sock = await task.socket_unix(socket.SOCK_STREAM)
    #             await rsyscall.io.robust_unix_connect(data_path, client_sock)
    #             server_fd = await near.accept4(task.base.sysif, listening_sock, None, None, os.O_CLOEXEC)
    #     trio.run(test)

    async def foo(self) -> None:
        async with trio.open_nursery() as nursery:
            async def thing1() -> None:
                await trio.sleep(0)
                raise Exception("ha ha")
            async def thing2() -> None:
                await trio.sleep(1000)
            nursery.start_soon(thing1)
            nursery.start_soon(thing2)

    def test_nursery(self) -> None:
        async def test() -> None:
            async with trio.open_nursery() as nursery:
                async def a1() -> None:
                    await trio.sleep(10)
                async def a2() -> None:
                    try:
                        await self.foo()
                    except:
                        print("hello")
                    finally:
                        nursery.cancel_scope.cancel()
                nursery.start_soon(a1)
                nursery.start_soon(a2)
        trio.run(test)
        

if __name__ == '__main__':
    import unittest
    unittest.main()


