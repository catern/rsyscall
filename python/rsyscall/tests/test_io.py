import typing as t
from rsyscall._raw import ffi, lib # type: ignore
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
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor, EpollThread
from rsyscall.memory.ram import RAMThread

from rsyscall.tasks.stdin_bootstrap import rsyscall_stdin_bootstrap
from rsyscall.tasks.stub import StubServer
from rsyscall.tasks.ssh import make_local_ssh
import rsyscall.tasks.local as local
from rsyscall.tasks.exec import spawn_exec

import rsyscall.inotify_watch as inotify
from rsyscall.sys.epoll import EpollEvent, EPOLL
from rsyscall.sys.capability import CAP, CapHeader, CapData
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
        logger.info("async test read: starting")
        result = await async_pipe_rfd.read_some_bytes()
        logger.info("async test read: returned")
        self.assertEqual(result, data)
    async with trio.open_nursery() as nursery:
        nursery.start_soon(stuff)
        await trio.sleep(0.01)
        # hmmm MMM MMMmmmm MMM mmm MMm mm MM mmm MM mm MM
        # does this make sense?
        logger.info("async test write: starting")
        await async_pipe_wfd.write_all_bytes(data)
        logger.info("async test write: returned")
    await async_pipe_rfd.close()
    await async_pipe_wfd.close()

async def assert_thread_works(self: unittest.TestCase, thr: EpollThread) -> None:
    await do_async_things(self, thr.epoller, thr)

class TestIO(unittest.TestCase):
    async def do_async_things(self, epoller, thr: RAMThread) -> None:
        await do_async_things(self, epoller, thr)

    async def runner(self, test: t.Callable[[StandardTask], t.Awaitable[None]]) -> None:
        async with trio.open_nursery() as nursery:
            await test(local.thread)

    async def runner_with_tempdir(
            self,
            test: t.Callable[[StandardTask, rsyscall.path.Path], t.Awaitable[None]]
    ) -> None:
        stdtask = local.thread
        async with trio.open_nursery() as nursery:
            async with (await stdtask.mkdtemp()) as tmppath:
                await test(stdtask, tmppath)

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

    def test_async(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            await self.do_async_things(stdtask.epoller, stdtask)
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
                    await self.do_async_things(stdtask3.epoller, stdtask3)
        trio.run(self.runner, test)

    @unittest.skip("Nix deploy is broken")
    def test_ssh_nix_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            host = await make_local_ssh(stdtask, rsyscall.nix.local_store)
            local_child, remote_stdtask = await host.ssh(stdtask)
            thread = await remote_stdtask.fork()
            src_nix_bin = stdtask.task.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.nix.create_nix_container(src_nix_bin, stdtask, thread)
            # let's use nix-copy-closure or nix-store --import/--export or nix copy to copy bash over then run it?
            # nix-store --import/--export
            bash = await stdtask.environ.which("bash")
            dest_bash = await rsyscall.nix.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, thread)
            child_task = await thread.execve(dest_bash, ["bash"])
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

    @unittest.skip("Nix deploy is broken")
    def test_nix_shell(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            thread = await stdtask.fork()
            src_nix_bin = stdtask.task.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.nix.create_nix_container(src_nix_bin, stdtask, thread)
            bash = await stdtask.environ.which("bash")
            dest_bash = await rsyscall.nix.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, thread)
            child_task = await thread.execve(dest_bash, ["bash", "--norc"])
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

    @unittest.skip("Nix deploy is broken")
    def test_nix_shell_with_daemon(self) -> None:
        async def test(stdtask: StandardTask) -> None:
            del stdtask.environ['NIX_REMOTE']
            thread = await stdtask.fork()
            src_nix_bin = stdtask.task.make_path_from_bytes(nix_bin_bytes)
            dest_nix_bin = await rsyscall.nix.create_nix_container(src_nix_bin, stdtask, thread)
            child_task = await thread.execve(dest_nix_bin/"nix-daemon", ["nix-daemon"], {'NIX_REMOTE':''})

            shell_thread = await stdtask.fork()
            dest_nix_bin = shell_thread.task.make_path_handle(dest_nix_bin)
            with child_task.process.borrow():
                ns_user = rsyscall.path.Path("/proc")/str(child_task.process.near.id)/"ns"/"user"
                usernsfd = await shell_thread.task.open(await shell_thread.ram.to_pointer(ns_user), O.RDONLY|O.CLOEXEC)
            await shell_thread.setns_user(usernsfd)
            await shell_thread.unshare_mount()
            await shell_thread.mount(b"nix", b"/nix", b"none", MS.BIND|MS.RDONLY, b"")
            # making a readonly bind mount is weird, you have to mount it first then remount it rdonly
            await shell_thread.mount(b"none", b"/nix", b"none",
                                             MS.BIND|MS.REMOUNT|MS.RDONLY, b"")
            bash = await stdtask.environ.which("bash")
            dest_bash = await rsyscall.nix.nix_deploy(src_nix_bin, bash.executable_path, stdtask, dest_nix_bin, shell_thread)
            mount = await stdtask.environ.which("mount")
            # don't seem to be able to copy coreutils for some reason?
            # it doesn't have a valid signature?
            await rsyscall.nix.nix_deploy(src_nix_bin, mount.executable_path,
                                         stdtask, dest_nix_bin, shell_thread)
            child_task = await shell_thread.execve(dest_bash, ["bash", "--norc"])
            await child_task.wait_for_exit()
        trio.run(self.runner, test)

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


