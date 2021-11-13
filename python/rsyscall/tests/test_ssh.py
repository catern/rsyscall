from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase
import rsyscall.thread
from rsyscall.nix import enter_nix_container, deploy
import rsyscall._nixdeps.nix
import rsyscall._nixdeps.coreutils
from rsyscall.tasks.ssh import *
from rsyscall import local_thread

from rsyscall.unistd import SEEK
from rsyscall.signal import Sigset, HowSIG
from rsyscall.sys.mman import MFD
from rsyscall.sched import CLONE

from rsyscall.handle import FileDescriptor
from rsyscall.thread import Thread, Command
from rsyscall.command import Command
from rsyscall.monitor import AsyncChildProcess
from rsyscall.stdlib import mkdtemp

# import logging
# logging.basicConfig(level=logging.DEBUG)

async def start_cat(thread: Thread, cat: Command,
                    stdin: FileDescriptor, stdout: FileDescriptor) -> AsyncChildProcess:
    thread = await thread.clone()
    await thread.task.inherit_fd(stdin).dup2(thread.stdin)
    await thread.task.inherit_fd(stdout).dup2(thread.stdout)
    child = await thread.exec(cat)
    return child

class TestSSH(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.host = await make_local_ssh(self.local)
        self.local_child, self.remote = await self.host.ssh(self.local)

    async def asyncTearDown(self) -> None:
        await self.local_child.kill()

    async def test_read(self) -> None:
        [(local_sock, remote_sock)] = await self.remote.open_channels(1)
        data = b"hello world"
        await local_sock.write(await self.local.ram.ptr(data))
        valid, _ = await remote_sock.read(await self.remote.ram.malloc(bytes, len(data)))
        self.assertEqual(len(data), valid.size())
        self.assertEqual(data, await valid.read())

    async def test_connection_multiple_channels(self) -> None:
        """Test that using open_channels(n) for n > 1 produces working channels.

        Our parallelization for this function was previously buggy and broke the channels.
        """
        [
            (local_sock, remote_sock),
            *rest,
        ] = await self.remote.open_channels(10)
        data = b'foobar'
        _, remaining = await local_sock.write(await local_thread.ptr(data))
        self.assertEqual(remaining.size(), 0, msg="Got partial write")
        read_data, _ = await remote_sock.read(await self.remote.malloc(bytes, len(data)))
        self.assertEqual(data, await read_data.read())

    async def test_exec_true(self) -> None:
        true = (await deploy(self.local, rsyscall._nixdeps.coreutils.closure)).bin('true')
        await self.remote.run(true)

    async def test_exec_pipe(self) -> None:
        [(local_sock, remote_sock)] = await self.remote.open_channels(1)
        cat = (await deploy(self.local, rsyscall._nixdeps.coreutils.closure)).bin('cat')
        thread = await self.remote.clone()
        cat_side = thread.task.inherit_fd(remote_sock)
        await remote_sock.close()
        await cat_side.dup2(thread.stdin)
        await cat_side.dup2(thread.stdout)
        child_process = await thread.exec(cat)

        in_data = await self.local.ram.ptr(b"hello")
        written, _ = await local_sock.write(in_data)
        valid, _ = await local_sock.read(written)
        self.assertEqual(in_data.value, await valid.read())

    async def test_clone(self) -> None:
        thread1 = await self.remote.clone()
        thread2 = await thread1.clone()
        await thread2.exit(0)
        await thread1.exit(0)

    async def test_nest(self) -> None:
        local_child, remote = await self.host.ssh(self.remote)
        await local_child.kill()

    async def test_copy(self) -> None:
        cat = (await deploy(self.local, rsyscall._nixdeps.coreutils.closure)).bin('cat')

        local_file = await self.local.task.memfd_create(await self.local.ptr("source"))
        remote_file = await self.remote.task.memfd_create(await self.remote.ptr("dest"))

        data = b'hello world'
        await local_file.write(await self.local.ram.ptr(data))
        await local_file.lseek(0, SEEK.SET)

        [(local_sock, remote_sock)] = await self.remote.open_channels(1)

        local_child = await start_cat(self.local, cat, local_file, local_sock)
        await local_sock.close()

        remote_child = await start_cat(self.remote, cat, remote_sock, remote_file)
        await remote_sock.close()

        await local_child.check()
        await remote_child.check()

        await remote_file.lseek(0, SEEK.SET)
        read, _ = await remote_file.read(await self.remote.ram.malloc(bytes, len(data)))
        self.assertEqual(await read.read(), data)

    async def test_sigmask_bug(self) -> None:
        thread = await self.remote.clone()
        await rsyscall.thread.do_cloexec_except(
            thread, set([fd.near for fd in thread.task.fd_handles]))
        await self.remote.task.sigprocmask((HowSIG.SETMASK,
                                            await self.remote.ram.ptr(Sigset())),
                                           await self.remote.ram.malloc(Sigset))
        await self.remote.task.read_oldset_and_check()

    async def test_nix_deploy(self) -> None:
        # make it locally so that it can be cleaned up even when the
        # remote enters the container
        tmpdir = await mkdtemp(self.local)
        async with tmpdir:
            await enter_nix_container(self.local, rsyscall._nixdeps.nix.closure, self.remote, tmpdir)
            hello = (await deploy(self.remote, rsyscall._nixdeps.coreutils.closure)).bin('echo').args('hello world')
            await self.remote.run(hello)
