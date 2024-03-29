from __future__ import annotations

from rsyscall import AsyncChildPid, Process
from rsyscall.tests.trio_test_case import TrioTestCase
import rsyscall.thread
from rsyscall.nix import enter_nix_container, deploy
import rsyscall._nixdeps.nix
import rsyscall._nixdeps.coreutils
from rsyscall.tasks.ssh import *

from rsyscall.unistd import SEEK
from rsyscall.signal import Sigset, HowSIG
from rsyscall.sys.mman import MFD
from rsyscall.sched import CLONE

from rsyscall.handle import FileDescriptor
from rsyscall.thread import Process, Command
from rsyscall.command import Command
from rsyscall.monitor import AsyncChildPid
from rsyscall.stdlib import mkdtemp

# import logging
# logging.basicConfig(level=logging.DEBUG)

async def start_cat(process: Process, cat: Command,
                    stdin: FileDescriptor, stdout: FileDescriptor) -> AsyncChildPid:
    process = await process.fork()
    await process.task.inherit_fd(stdin).dup2(process.stdin)
    await process.task.inherit_fd(stdout).dup2(process.stdout)
    child = await process.exec(cat)
    return child

class TestSSH(TrioTestCase):
    host: SSHHost
    local_child: AsyncChildPid
    remote: Process

    @classmethod
    async def asyncSetUpClass(cls) -> None:
        cls.host = await make_local_ssh(cls.process)
        cls.local_child, cls.remote = await cls.host.ssh(cls.process)

    @classmethod
    async def asyncTearDownClass(cls) -> None:
        await cls.local_child.kill()

    async def test_read(self) -> None:
        [(local_sock, remote_sock)] = await self.remote.open_channels(1)
        data = b"hello world"
        await local_sock.write(await self.process.task.ptr(data))
        valid, _ = await remote_sock.read(await self.remote.task.malloc(bytes, len(data)))
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
        _, remaining = await local_sock.write(await self.process.ptr(data))
        self.assertEqual(remaining.size(), 0, msg="Got partial write")
        read_data, _ = await remote_sock.read(await self.remote.malloc(bytes, len(data)))
        self.assertEqual(data, await read_data.read())

    async def test_exec_true(self) -> None:
        true = (await deploy(self.process, rsyscall._nixdeps.coreutils.closure)).bin('true')
        await self.remote.run(true)

    async def test_exec_pipe(self) -> None:
        [(local_sock, remote_sock)] = await self.remote.open_channels(1)
        cat = (await deploy(self.process, rsyscall._nixdeps.coreutils.closure)).bin('cat')
        process = await self.remote.fork()
        cat_side = process.task.inherit_fd(remote_sock)
        await remote_sock.close()
        await cat_side.dup2(process.stdin)
        await cat_side.dup2(process.stdout)
        child_pid = await process.exec(cat)

        in_data = await self.process.task.ptr(b"hello")
        written, _ = await local_sock.write(in_data)
        valid, _ = await local_sock.read(written)
        self.assertEqual(in_data.value, await valid.read())

    async def test_clone(self) -> None:
        process1 = await self.remote.fork()
        process2 = await process1.fork()
        await process2.exit(0)
        await process1.exit(0)

    async def test_nest(self) -> None:
        local_child, remote = await self.host.ssh(self.remote)
        await local_child.kill()

    async def test_copy(self) -> None:
        cat = (await deploy(self.process, rsyscall._nixdeps.coreutils.closure)).bin('cat')

        local_file = await self.process.task.memfd_create(await self.process.ptr("source"))
        remote_file = await self.remote.task.memfd_create(await self.remote.ptr("dest"))

        data = b'hello world'
        await local_file.write(await self.process.task.ptr(data))
        await local_file.lseek(0, SEEK.SET)

        [(local_sock, remote_sock)] = await self.remote.open_channels(1)

        local_child = await start_cat(self.process, cat, local_file, local_sock)
        await local_sock.close()

        remote_child = await start_cat(self.remote, cat, remote_sock, remote_file)
        await remote_sock.close()

        await local_child.check()
        await remote_child.check()

        await remote_file.lseek(0, SEEK.SET)
        read, _ = await remote_file.read(await self.remote.task.malloc(bytes, len(data)))
        self.assertEqual(await read.read(), data)

    async def test_sigmask_bug(self) -> None:
        process = await self.remote.fork()
        await rsyscall.thread.do_cloexec_except(
            process, set([fd.near for fd in process.task.fd_handles]))
        await self.remote.task.sigprocmask((HowSIG.SETMASK,
                                            await self.remote.task.ptr(Sigset())),
                                           await self.remote.task.malloc(Sigset))
        await self.remote.task.read_oldset_and_check()

    async def test_nix_deploy(self) -> None:
        # make it locally so that it can be cleaned up even when the
        # remote enters the container
        tmpdir = await mkdtemp(self.process)
        async with tmpdir:
            await enter_nix_container(self.process, rsyscall._nixdeps.nix.closure, self.remote, tmpdir)
            true = (await deploy(self.remote, rsyscall._nixdeps.coreutils.closure)).bin('true')
            await self.remote.run(true)
