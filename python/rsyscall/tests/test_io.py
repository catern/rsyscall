import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.io import StandardTask
from rsyscall.command import Command
import rsyscall.io as rsc
import shutil
import rsyscall.near as near
import rsyscall.far as far
import socket
import struct
import time
import unittest
import trio
import trio.hazmat
import rsyscall.io
import os
import rsyscall.path
import rsyscall.repl
import rsyscall.wish
import rsyscall.nix

from rsyscall.handle import WrittenPointer, Pointer
from rsyscall.epoller import EpollCenter
from rsyscall.memory.ram import RAMThread

from rsyscall.tasks.persistent import fork_persistent
from rsyscall.tasks.stdin_bootstrap import rsyscall_stdin_bootstrap
from rsyscall.tasks.stub import StubServer
from rsyscall.tasks.ssh import make_local_ssh
import rsyscall.tasks.local as local
from rsyscall.tasks.exec import spawn_exec

import rsyscall.inotify_watch as inotify
from rsyscall.sys.epoll import EpollEvent, EPOLL
from rsyscall.sys.capability import CAP, CapHeader, CapData
from rsyscall.sys.prctl import PrctlOp, CapAmbient
from rsyscall.sys.socket import SOCK, AF, Address
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.uio import RWF, IovecList
from rsyscall.linux.netlink import NETLINK
from rsyscall.linux.dirent import DirentList
from rsyscall.signal import Signals, Sigset
from rsyscall.sys.signalfd import SignalfdSiginfo
from rsyscall.net.if_ import Ifreq
from rsyscall.unistd import SEEK, Pipe
from rsyscall.fcntl import O
from rsyscall.sys.mount import MS

from rsyscall.struct import Bytes

from rsyscall.monitor import SignalQueue


import logging
logger = logging.getLogger(__name__)

# logging.basicConfig(level=logging.DEBUG)

nix_bin_bytes = b"/nix/store/wpbag7vnmr4pr9p8a3003s68907w9bxq-nix-2.2pre6600_85488a93/bin"
async def do_async_things(self: unittest.TestCase, epoller, thr: RAMThread) -> None:
    pipe = await (await thr.task.pipe(await thr.ram.malloc_struct(Pipe))).read()
    async_pipe_rfd = await AsyncFileDescriptor.make_handle(epoller, thr.ram, pipe.read)
    async_pipe_wfd = await AsyncFileDescriptor.make_handle(epoller, thr.ram, pipe.write)
    data = b"hello world"
    async def stuff():
        logger.info("performing read")
        result = await async_pipe_rfd.read_some_bytes()
        self.assertEqual(result, data)
    async with trio.open_nursery() as nursery:
        nursery.start_soon(stuff)
        await trio.sleep(0.01)
        logger.info("performing write")
        # hmmm MMM MMMmmmm MMM mmm MMm mm MM mmm MM mm MM
        # does this make sense?
        await async_pipe_wfd.write_all_bytes(data)
    await async_pipe_rfd.aclose()
    await async_pipe_wfd.aclose()

class TestIO(unittest.TestCase):
    async def do_async_things(self, epoller, thr: RAMThread) -> None:
        await do_async_things(self, epoller, thr)

    async def runner(self, test: t.Callable[[StandardTask], t.Awaitable[None]]) -> None:
        async with trio.open_nursery() as nursery:
            await test(local.stdtask)

    async def runner_with_tempdir(
            self,
            test: t.Callable[[StandardTask, rsyscall.path.Path], t.Awaitable[None]]
    ) -> None:
        stdtask = local.stdtask
        async with trio.open_nursery() as nursery:
            async with (await stdtask.mkdtemp()) as tmppath:
                await test(stdtask, tmppath)

    def test_pipe(self):
        async def test(stdtask: StandardTask) -> None:
            pipe = await (await stdtask.task.base.pipe(await stdtask.ram.malloc_struct(Pipe), O.CLOEXEC)).read()
            in_data = b"hello"
            written, _ = await pipe.write.write(await stdtask.ram.to_pointer(Bytes(in_data)))
            valid, _ = await pipe.read.read(written)
            self.assertEqual(in_data, await valid.read())
        trio.run(self.runner, test)

    def test_readv(self):
        async def test(stdtask: StandardTask) -> None:
            task = stdtask.task.base
            ram = stdtask.ram
            pipe = await (await task.pipe(await ram.malloc_struct(Pipe), O.CLOEXEC)).read()
            in_data = [b"hello", b"world"]
            iov = await ram.to_pointer(IovecList([await ram.to_pointer(Bytes(data)) for data in in_data]))
            written, partial, rest = await pipe.write.writev(iov)
            self.assertEqual(partial, None, msg="got unexpected partial write")
            self.assertEqual(rest.bytesize(), 0, msg="got unexpected partial write")
            read, partial, rest = await pipe.read.readv(written)
            self.assertEqual(partial, None, msg="got unexpected partial read")
            self.assertEqual(rest.bytesize(), 0, msg="got unexpected partial read")
            self.assertEqual(in_data, [await ptr.read() for ptr in read.value])
        trio.run(self.runner, test)

    def test_recv_pipe(self) -> None:
        """Sadly, recv doesn't work on pipes

        Which is a major bummer, because that would allow us to avoid
        messing with O_NONBLOCk stuff

        """
        async def test(stdtask: StandardTask) -> None:
            pipe = await (await stdtask.task.base.pipe(await stdtask.ram.malloc_struct(Pipe), O.CLOEXEC)).read()
            in_data = b"hello"
            written, _ = await pipe.write.write(await stdtask.ram.to_pointer(Bytes(in_data)))
            with self.assertRaises(OSError):
                valid, _ = await pipe.read.recv(written, 0)
        trio.run(self.runner, test)

    def test_to_pointer(self):
        async def test(stdtask: StandardTask) -> None:
            event = EpollEvent(42, EPOLL.NONE)
            ptr = await stdtask.ram.to_pointer(event)
            read_event = await ptr.read()
            self.assertEqual(event.data, read_event.data)
            
            ifreq = Ifreq()
            ifreq.name = b"1234"
            ifreq.ifindex = 13
            iptr = await stdtask.ram.to_pointer(ifreq)
            read_ifreq = await iptr.read()
            self.assertEqual(read_ifreq.ifindex, ifreq.ifindex)
            self.assertEqual(read_ifreq.name, ifreq.name)
        trio.run(self.runner, test)

    def test_readlinkat_non_symlink(self):
        async def test(stdtask: StandardTask) -> None:
            f = await stdtask.task.base.open(await stdtask.ram.to_pointer(rsyscall.path.Path(".")), O.PATH|O.CLOEXEC)
            empty_ptr = await stdtask.ram.to_pointer(rsyscall.path.EmptyPath())
            ptr = await stdtask.ram.malloc_type(rsyscall.path.Path, 4096)
            with self.assertRaises(FileNotFoundError):
                await f.readlinkat(empty_ptr, ptr)
        trio.run(self.runner, test)

    def test_readlink_proc(self):
        async def test(stdtask: StandardTask) -> None:
            f = await stdtask.task.base.open(await stdtask.ram.to_pointer(rsyscall.path.Path(".")), O.PATH|O.CLOEXEC)
            path_ptr = await stdtask.ram.to_pointer(f.as_proc_self_path())
            ptr = await stdtask.ram.malloc_type(rsyscall.path.Path, 4096)
            await f.readlinkat(path_ptr, ptr)
        trio.run(self.runner, test)

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

    def test_async(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            await self.do_async_things(stdtask.epoller, stdtask.ramthr)
        trio.run(self.runner, test)

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
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp()) as path:
                dirfd = await stdtask.task.base.open(await stdtask.ram.to_pointer(path), O.DIRECTORY)
                dent_buf = await stdtask.ram.malloc_type(DirentList, 4096)
                valid, rest = await dirfd.getdents(dent_buf)
                self.assertCountEqual(sorted([dirent.name for dirent in await valid.read()]), ['.', '..'])
                dent_buf = valid + rest

                text = b"Hello world!"
                name = await stdtask.ram.to_pointer(rsyscall.path.Path("hello"))

                write_fd = await dirfd.openat(name, O.WRONLY|O.CREAT)
                buf = await stdtask.ram.to_pointer(Bytes(text))
                written, _ = await write_fd.write(buf)

                read_fd = await dirfd.openat(name, O.RDONLY)
                read, _ = await read_fd.read(written)
                self.assertEqual(await read.read(), text)

                await dirfd.lseek(0, SEEK.SET)
                valid, rest = await dirfd.getdents(dent_buf)
                self.assertCountEqual(sorted([dirent.name for dirent in await valid.read()]),
                                      ['.', '..', str(name.value)])
        trio.run(self.runner, test)

    # def test_bind(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await stdtask.task.socket_unix(SOCK.STREAM)) as sockfd:
    #                     addr = SockaddrUn.from_path(path/"sock")
    #                     await sockfd.bind(addr)
    #     trio.run(test)

    def test_listen(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp()) as path:
                sockfd = await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.CLOEXEC)
                addr: WrittenPointer[Address] = await stdtask.ram.to_pointer(
                    await SockaddrUn.from_path(stdtask, path/"sock"))
                await sockfd.bind(addr)
                await sockfd.listen(10)
                clientfd = await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.CLOEXEC)
                await clientfd.connect(addr)
                connfd = await sockfd.accept(SOCK.CLOEXEC)
        trio.run(self.runner, test)

    def test_listen_async(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp()) as path:
                sockfd = await stdtask.make_afd(
                    await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
                addr: WrittenPointer[Address] = await stdtask.ram.to_pointer(
                    await SockaddrUn.from_path(stdtask, path/"sock"))
                await sockfd.handle.bind(addr)
                await sockfd.handle.listen(10)
                clientfd = await stdtask.make_afd(
                    await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
                await clientfd.connect_ptr(addr)
                connfd, client_addr = await sockfd.accept_addr()
                logger.info("%s, %s", addr, client_addr)
                await connfd.close()
                await sockfd.close()
                await clientfd.close()
        trio.run(self.runner, test)

    def test_listen_async_accept(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp()) as path:
                sockfd = await stdtask.make_afd(
                    await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
                addr: WrittenPointer[Address] = await stdtask.ram.to_pointer(
                    await SockaddrUn.from_path(stdtask, path/"sock"))
                await sockfd.handle.bind(addr)
                await sockfd.handle.listen(10)

                clientfd = await stdtask.make_afd(
                    await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
                await clientfd.connect_ptr(addr)

                connfd_h, client_addr = await sockfd.accept_addr(SOCK.CLOEXEC|SOCK.NONBLOCK)
                connfd = await sockfd.thr.make_afd(connfd_h)
                logger.info("%s, %s", addr, client_addr)
                data = b"hello"
                await connfd.write_all_bytes(data)
                self.assertEqual(data, await clientfd.read_some_bytes())
                await connfd.close()
                await sockfd.close()
                await clientfd.close()
        trio.run(self.runner, test)

    def test_pure_repl(self) -> None:
        async def test() -> None:
            repl = rsyscall.repl.PureREPL({})
            async def eval(line: str) -> t.Any:
                result = await repl.add_line(line + '\n')
                if isinstance(result, rsyscall.repl.ExpressionResult):
                    return result.value
                else:
                    raise Exception("unexpected", result)
            self.assertEqual(await eval('1'), 1)
            self.assertEqual(await eval('1+1'), 2)
            await repl.add_line('foo = 1\n')
            self.assertEqual(await eval('foo*4'), 4)
        rsyscall.repl.await_pure(test())

    def test_repl(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp()) as path:
                sockfd = await stdtask.make_afd(
                    await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
                addr: WrittenPointer[Address] = await stdtask.ram.to_pointer(
                    await SockaddrUn.from_path(stdtask, path/"sock"))
                await sockfd.handle.bind(addr)
                await sockfd.handle.listen(10)
                clientfd = await stdtask.make_afd(
                    await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK|SOCK.CLOEXEC), nonblock=True)
                await clientfd.connect_ptr(addr)
                await clientfd.write_all_bytes(b"foo = 11\n")
                await clientfd.write_all_bytes(b"return foo * 2\n")
                ret = await rsyscall.wish.serve_repls(sockfd, {'locals': locals()}, int, "hello")
                self.assertEqual(ret, 22)
        trio.run(self.runner, test)

    # def test_robust_bind_connect(self) -> None:
    #     "robust_unix_bind and robust_unix_connect work correctly on long Unix socket paths"
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             async with (await stdtask.mkdtemp()) as path:
    #                 async with (await stdtask.task.socket_unix(SOCK.STREAM)) as sockfd:
    #                     sockpath = path/("long"*25 + "sock")
    #                     await rsyscall.io.robust_unix_bind(sockpath, sockfd)
    #                     await sockfd.listen(10)
    #                     async with (await stdtask.task.socket_unix(SOCK.STREAM)) as clientfd:
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
    #              async with (await stdtask.task.socket_inet(SOCK.STREAM)) as sockfd:
    #                  bind_addr = sockfd.file.address_type(0, 0x7F_00_00_01)
    #                  await sockfd.bind(bind_addr)
    #                  addr = await sockfd.getsockname()
    #                  await sockfd.listen(10)
    #                  async with (await AsyncFileDescriptor.make(stdtask.resources.epoller, sockfd)) as async_sockfd:
    #                      clientfd = await stdtask.task.socket_inet(SOCK.STREAM)
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
    #              async with (await stdtask.task.socket_inet(SOCK.DGRAM)) as recv_sockfd:
    #                  await recv_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
    #                  addr_recv = await recv_sockfd.getsockname()
    #                  async with (await stdtask.task.socket_inet(SOCK.DGRAM)) as send1_sockfd:
    #                      await send1_sockfd.bind(recv_sockfd.file.address_type(0, 0x7F_00_00_01))
    #                      addr_send1 = await send1_sockfd.getsockname()
    #                      await recv_sockfd.connect(addr_send1)
    #                      await send1_sockfd.connect(addr_recv)
    #                      async with (await stdtask.task.socket_inet(SOCK.DGRAM)) as send2_sockfd:
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

    def test_pidns_nest(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)
            async with thread as stdtask2:
                thread2 = await spawn_exec(stdtask2, rsyscall.nix.local_store)
                async with thread2 as stdtask3:
                    await self.do_async_things(stdtask3.epoller, stdtask3.ramthr)
        trio.run(self.runner, test)

    def test_setns_ownership(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread1 = await stdtask.fork()
            await thread1.stdtask.unshare_user()
            await thread1.stdtask.unshare_net()
            procselfns = rsyscall.path.Path("/proc/self/ns")
            netnsfd = await thread1.task.base.open(await thread1.ram.to_pointer(procselfns/"net"), O.RDONLY|O.CLOEXEC)

            thread2 = await stdtask.fork()
            await thread2.stdtask.unshare_user()
            with self.assertRaises(PermissionError):
                # we can't setns to a namespace that we don't own, I guess...
                await thread2.stdtask.task.base.setns_net(netnsfd)
                # that's really lame...
        trio.run(self.runner, test)

    def test_make_tun(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            import rsyscall.net.if_ as net
            await stdtask.unshare_user()
            await stdtask.unshare_net()

            tunpath = rsyscall.path.Path("/dev/net/tun")
            tun_fd = await stdtask.task.base.open(await stdtask.ram.to_pointer(tunpath), O.RDWR|O.CLOEXEC)
            ptr = await stdtask.ram.to_pointer(net.Ifreq(b'tun0', flags=net.IFF_TUN))
            await tun_fd.ioctl(net.TUNSETIFF, ptr)
            sock = await stdtask.task.base.socket(AF.INET, SOCK.STREAM)
            await sock.ioctl(net.SIOCGIFINDEX, ptr)
            # this is the second interface in an empty netns
            self.assertEqual((await ptr.read()).ifindex, 2)
        trio.run(self.runner, test)

    def test_rtnetlink(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            from rsyscall.linux.netlink import SockaddrNl
            from rsyscall.linux.rtnetlink import RTMGRP
            import rsyscall.net.if_ as net
            await stdtask.unshare_user()
            await stdtask.unshare_net()

            netsock = await stdtask.task.base.socket(AF.NETLINK, SOCK.DGRAM, NETLINK.ROUTE)
            await netsock.bind(await stdtask.ram.to_pointer(SockaddrNl(0, RTMGRP.LINK)))

            tunpath = rsyscall.path.Path("/dev/net/tun")
            tun_fd = await stdtask.task.base.open(await stdtask.ram.to_pointer(tunpath), O.RDWR|O.CLOEXEC)
            ptr = await stdtask.ram.to_pointer(net.Ifreq(b'tun0', flags=net.IFF_TUN))
            await tun_fd.ioctl(net.TUNSETIFF, ptr)
            sock = await stdtask.task.base.socket(AF.INET, SOCK.STREAM)
            await sock.ioctl(net.SIOCGIFINDEX, ptr)
            # this is the second interface in an empty netns
            self.assertEqual((await ptr.read()).ifindex, 2)

            valid, _ = await netsock.read(await stdtask.ram.malloc_type(Bytes, 4096))
            from pyroute2 import IPBatch
            batch = IPBatch()
            evs = batch.marshal.parse(await valid.read())
        trio.run(self.runner, test)

    def test_ambient_caps(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            await stdtask.unshare_user()
            await stdtask.unshare_net()
            hdr_ptr = await stdtask.ram.to_pointer(CapHeader())
            data_ptr = await stdtask.ram.malloc_struct(CapData)
            await stdtask.task.base.capget(hdr_ptr, data_ptr)
            data = await data_ptr.read()
            data.inheritable.add(CAP.NET_ADMIN)
            data_ptr = await data_ptr.write(data)
            await stdtask.task.base.capset(hdr_ptr, data_ptr)
            await stdtask.task.base.prctl(PrctlOp.CAP_AMBIENT, CapAmbient.RAISE, CAP.NET_ADMIN)
        trio.run(self.runner, test)

    def test_sigaction(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            from rsyscall.signal import Sighandler, Sigaction, Sigset, Signals
            import readline
            sa = Sigaction(Sighandler.DFL)
            ptr = await stdtask.ram.to_pointer(sa)
            await stdtask.task.base.sigaction(Signals.SIGWINCH, ptr, None)
            await stdtask.task.base.sigaction(Signals.SIGWINCH, None, ptr)
            out_sa = await ptr.read()
            self.assertEqual(sa.handler, out_sa.handler)
            self.assertEqual(sa.flags, out_sa.flags)
            self.assertEqual(sa.mask, out_sa.mask)
            self.assertEqual(sa.restorer, out_sa.restorer)
        trio.run(self.runner, test)

    def test_spawn_exit(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await spawn_exec(stdtask, rsyscall.nix.local_store)
            async with thread as stdtask2:
                await stdtask2.exit(0)
        trio.run(self.runner, test)

    def test_spawn_basic(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await spawn_exec(stdtask, rsyscall.nix.local_store)
            async with thread as stdtask2:
                await self.do_async_things(stdtask2.epoller, stdtask2.ramthr)
        trio.run(self.runner, test)

    def test_spawn_nest(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread1 = await spawn_exec(stdtask, rsyscall.nix.local_store)
            async with thread1 as stdtask2:
                thread2 = await spawn_exec(stdtask2, rsyscall.nix.local_store)
                async with thread2 as stdtask3:
                    await self.do_async_things(stdtask3.epoller, stdtask3.ramthr)
        trio.run(self.runner, test)

    def test_thread_nest_async(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread1 = await stdtask.fork()
            async with thread1 as stdtask2:
                thread2 = await stdtask2.fork()
                async with thread2 as stdtask3:
                    await self.do_async_things(stdtask3.epoller, stdtask3.ramthr)
        trio.run(self.runner, test)

    def test_thread_exit(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                await stdtask2.exit(0)
        trio.run(self.runner, test)

    def test_inotify_create(self) -> None:
        async def test(stdtask: StandardTask, path: rsyscall.path.Path) -> None:
            inty = await inotify.Inotify.make(stdtask)
            watch = await inty.add(path, inotify.IN.CREATE)
            fd = await stdtask.task.open(await stdtask.ram.to_pointer(path/"foo"), O.CREAT|O.EXCL)
            await watch.wait_until_event(inotify.IN.CREATE, "foo")
        trio.run(self.runner_with_tempdir, test)

    @unittest.skip("not working right now")
    def test_ssh_persistent_thread_reconnect(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp("rsyscall_state")) as path:
                host = await make_local_ssh(stdtask, rsyscall.nix.local_store)
                local_child, remote_stdtask = await host.ssh(stdtask)
                # TODO need to have notion of "Host",
                # which I can pull the namespaces out of. hm.
                # it's to represent that two ssh connections to the same place,
                # will have the same,
                # namespaces and stuff.
                # probably.
                # so, okay. SSHHost perhaps?
                logger.info("about to fork")
                per_stdtask, server = await fork_persistent(remote_stdtask, path/"persist.sock")
                logger.info("forked persistent, %s", per_stdtask.task.base.process.near)
                await server.make_persistent()
                await local_child.kill()
                local_child, remote_stdtask = await host.ssh(stdtask)
                # OK, so it is indeed non-deterministic.
                # await per_stdtask.unshare_files()
                # await connection.rsyscall_connection.close()
                # hmm. if the connection is down then...
                # probably the data connection is down too...
                # AAA ok so the data connection is down. how do we repair it?
                # I guess we can just return the Transport as well as the Syscall,
                # and have a reconnectable transport thing.
                await server.reconnect(remote_stdtask)
                # don't have to unshare because the only other
                # thing in the fd space was the original ssh task.
                await per_stdtask.exit(0)
        trio.run(self.runner, test)

    def test_thread_nest_exit(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                thread3 = await stdtask2.fork()
                async with thread3 as stdtask3:
                    await stdtask3.exit(0)
        trio.run(self.runner, test)

    def test_thread_unshare(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                await stdtask2.unshare_files()
                thread3 = await stdtask2.fork()
                async with thread3 as stdtask3:
                    epoller = await EpollCenter.make_root(stdtask3.ram, stdtask3.task.base)
                    await stdtask3.unshare_files()
                    await self.do_async_things(epoller, stdtask3.ramthr)
        trio.run(self.runner, test)

    def test_thread_async(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                epoller = await EpollCenter.make_root(stdtask2.ram, stdtask2.task.base)
                await self.do_async_things(epoller, stdtask2.ramthr)
        trio.run(self.runner, test)

    def test_thread_exec(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                child_task = await thread.exec(stdtask.environ.sh.args('-c', 'sleep .01'))
                await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_thread_signal_queue(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            async with thread as stdtask2:
                # have to use an epoller for that specific task
                epoller = await EpollCenter.make_root(stdtask2.ram, stdtask2.task.base)
                sigqueue = await SignalQueue.make(stdtask2.ram, stdtask2.task.base,
                                                  epoller, Sigset({Signals.SIGINT}))
                await stdtask2.task.base.process.kill(Signals.SIGINT)
                buf = await stdtask2.ram.malloc_struct(SignalfdSiginfo)
                sigdata = await sigqueue.read(buf)
                self.assertEqual((await sigdata.read()).signo, Signals.SIGINT)
        trio.run(self.runner, test)

    @unittest.skip("requires a user")
    def test_ssh_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            host = await make_local_ssh(stdtask, rsyscall.nix.local_store)
            local_child, remote_stdtask = await host.ssh(stdtask)
            async with (await remote_stdtask.mkdtemp()) as remote_tmpdir:
                thread = await remote_stdtask.fork()
                bash = await remote_stdtask.environ.which("bash")
                await thread.task.chdir(await thread.ram.to_pointer(remote_tmpdir))
                child_task = await thread.exec(bash)
                await child_task.wait_for_exit()
        trio.run(self.runner, test)

    def test_copy(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            async with (await stdtask.mkdtemp()) as tmpdir:
                source_file = await stdtask.task.open(await stdtask.ram.to_pointer(tmpdir/"source"), O.RDWR|O.CREAT)
                data = b'hello world'
                buf: Pointer[Bytes] = await stdtask.ram.to_pointer(Bytes(data))
                valid, rest = await source_file.write(buf)
                buf = valid + rest
                await source_file.lseek(0, SEEK.SET)
                dest_file = await stdtask.task.open(await stdtask.ram.to_pointer(tmpdir/"dest"), O.RDWR|O.CREAT)

                thread = await stdtask.fork()
                cat = await stdtask.environ.which("cat")
                await thread.unshare_files_and_replace({
                    thread.stdin: source_file,
                    thread.stdout: dest_file,
                })
                child_process = await thread.exec(cat)
                await child_process.check()

                await dest_file.lseek(0, SEEK.SET)
                self.assertEqual(await (await dest_file.read(buf))[0].read(), data)
        trio.run(self.runner, test)

    @unittest.skip("Nix deploy is broken")
    def test_ssh_nix_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            host = await make_local_ssh(stdtask, rsyscall.nix.local_store)
            local_child, remote_stdtask = await host.ssh(stdtask)
            thread = await remote_stdtask.fork()
            src_nix_bin = stdtask.task.base.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.nix.create_nix_container(src_nix_bin, stdtask, thread.stdtask)
            # let's use nix-copy-closure or nix-store --import/--export or nix copy to copy bash over then run it?
            # nix-store --import/--export
            bash = await stdtask.environ.which("bash")
            dest_bash = await rsyscall.nix.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, thread.stdtask)
            child_task = await thread.execve(dest_bash, ["bash"])
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

    @unittest.skip("Nix deploy is broken")
    def test_nix_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            src_nix_bin = stdtask.task.base.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.nix.create_nix_container(src_nix_bin, stdtask, thread.stdtask)
            bash = await stdtask.environ.which("bash")
            dest_bash = await rsyscall.nix.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, thread.stdtask)
            child_task = await thread.execve(dest_bash, ["bash", "--norc"])
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

    @unittest.skip("Nix deploy is broken")
    def test_nix_shell_with_daemon(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            del stdtask.environ['NIX_REMOTE']
            thread = await stdtask.fork()
            src_nix_bin = stdtask.task.base.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.nix.create_nix_container(src_nix_bin, stdtask, thread.stdtask)
            child_task = await thread.execve(dest_nix_bin/"nix-daemon", ["nix-daemon"], {'NIX_REMOTE':''})

            shell_thread = await stdtask.fork()
            dest_nix_bin = shell_thread.stdtask.task.base.make_path_handle(dest_nix_bin)
            with child_task.process.borrow():
                ns_user = rsyscall.path.Path("/proc")/str(child_task.process.near.id)/"ns"/"user"
                usernsfd = await shell_thread.task.base.open(await shell_thread.ram.to_pointer(ns_user), O.RDONLY|O.CLOEXEC)
            await shell_thread.stdtask.setns_user(usernsfd)
            await shell_thread.stdtask.unshare_mount()
            await shell_thread.stdtask.mount(b"nix", b"/nix", b"none", MS.BIND|MS.RDONLY, b"")
            # making a readonly bind mount is weird, you have to mount it first then remount it rdonly
            await shell_thread.stdtask.mount(b"none", b"/nix", b"none",
                                             MS.BIND|MS.REMOUNT|MS.RDONLY, b"")
            bash = await stdtask.environ.which("bash")
            dest_bash = await rsyscall.nix.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, shell_thread.stdtask)
            mount = await stdtask.environ.which("mount")
            # don't seem to be able to copy coreutils for some reason?
            # it doesn't have a valid signature?
            await rsyscall.nix.nix_deploy(src_nix_bin, mount.executable_path,
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
    #         async with (await rsyscall.io.StandardTask.make_local()) as local.stdtask:
    #             rsyscall_task, _ = await local.stdtask.spawn([])
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
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, SOCK.STREAM, 0)
    #             in_data = b"hello"
    #             await l.write(in_data)
    #             out_data = await r.read(len(in_data))
    #             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    # def test_socketpair(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, SOCK.STREAM, 0)
    #             in_data = b"hello"
    #             await l.write(in_data)
    #             out_data = await r.read(len(in_data))
    #             self.assertEqual(in_data, out_data)
    #     trio.run(test)

    def test_pass_fd(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            from rsyscall.handle import (FDPair, SendMsghdr, RecvMsghdr, IovecList, SendmsgFlags, RecvmsgFlags,
                                         CmsgSCMRights, CmsgList, MsghdrFlags)
            task = stdtask.task
            ram = stdtask.ram
            fds = await (await task.base.socketpair(
                AF.UNIX, SOCK.STREAM|SOCK.CLOEXEC, 0,
                await ram.malloc_struct(FDPair))).read()
            in_data = b"hello"

            iovec = await ram.to_pointer(IovecList([await ram.to_pointer(Bytes(in_data))]))
            cmsgs = await ram.to_pointer(CmsgList([CmsgSCMRights([fds.second])]))
            [written], [] = await fds.second.sendmsg(
                await ram.to_pointer(SendMsghdr(None, iovec, cmsgs)), SendmsgFlags.NONE)

            [valid], [], hdr = await fds.first.recvmsg(
                await ram.to_pointer(RecvMsghdr(None, iovec, cmsgs)), RecvmsgFlags.NONE)

            self.assertEqual(in_data, await valid.read())

            hdrval = await hdr.read()
            [[passed_fd]] = await hdrval.control.read() # type: ignore
            self.assertEqual(hdrval.name, None)
            self.assertEqual(hdrval.flags, MsghdrFlags.NONE)
        trio.run(self.runner, test)

    def test_fork_exec(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            child_thread = await stdtask.fork()
            child_task = await child_thread.exec(stdtask.environ.sh.args('-c', 'true'))
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

    # def test_pass_fd_thread(self) -> None:
    #     async def test() -> None:
    #         async with (await rsyscall.io.StandardTask.make_local()) as stdtask:
    #             task = stdtask.task
    #             l, r = await stdtask.task.socketpair(socket.AF_UNIX, SOCK.STREAM, 0)
    #             rsyscall_task, [r_remote] = await stdtask.spawn([r.handle.far])
    #             async with rsyscall_task as stdtask2:
    #                 l2, r2 = await stdtask.task.socketpair(socket.AF_UNIX, SOCK.STREAM, 0)
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
                        pass
                    finally:
                        nursery.cancel_scope.cancel()
                nursery.start_soon(a1)
                nursery.start_soon(a2)
        trio.run(test)
        

# if __name__ == '__main__':
#     import unittest
#     unittest.main()


