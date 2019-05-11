from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.io
from rsyscall.nix import local_store
from rsyscall.misc import bash_nixdep, coreutils_nixdep
from rsyscall.struct import Bytes
from rsyscall.tasks.ssh import *
import rsyscall.tasks.local as local

from rsyscall.unistd import SEEK
from rsyscall.signal import Sigset, HowSIG
from rsyscall.sys.memfd import MFD

import rsyscall.handle as handle
from rsyscall.path import Path
from rsyscall.io import StandardTask, Command
from rsyscall.monitor import AsyncChildProcess

# import logging
# logging.basicConfig(level=logging.DEBUG)

async def start_cat(stdtask: StandardTask, cat: Command,
                    stdin: handle.FileDescriptor, stdout: handle.FileDescriptor) -> AsyncChildProcess:
    thread = await stdtask.fork()
    await thread.stdtask.unshare_files_and_replace({
        thread.stdtask.stdin.handle: stdin,
        thread.stdtask.stdout.handle: stdout,
    }, going_to_exec=True)
    child = await thread.exec(cat)
    return child

class TestSSH(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = local.stdtask
        self.task = self.stdtask.task.base
        self.ram = self.stdtask.task
        self.store = local_store
        self.host = await make_local_ssh(self.stdtask, self.store)
        self.local_child, self.remote_stdtask = await self.host.ssh(self.stdtask)
        self.remote_task = self.remote_stdtask.task.base
        self.remote_ram = self.remote_stdtask.task

    async def test_read(self) -> None:
        [(local_sock, remote_sock)] = await self.remote_stdtask.make_connections(1)
        data = Bytes(b"hello world")
        await local_sock.write(await self.stdtask.task.to_pointer(data))
        valid, _ = await remote_sock.read(await self.remote_stdtask.task.malloc_type(Bytes, len(data)))
        self.assertEqual(len(data), valid.bytesize())
        self.assertEqual(data, await valid.read())

    async def test_exec(self) -> None:
        bash = await self.store.bin(bash_nixdep, "bash")
        await self.remote_stdtask.run(bash.args('-c', 'true'))

    async def test_copy(self) -> None:
        cat = await self.store.bin(coreutils_nixdep, "cat")

        local_file = await self.task.memfd_create(await self.ram.to_pointer(Path("source")), MFD.CLOEXEC)
        remote_file = await self.remote_task.memfd_create(await self.remote_ram.to_pointer(Path("dest")), MFD.CLOEXEC)

        data = b'hello world'
        await local_file.write(await self.ram.to_pointer(Bytes(data)))
        await local_file.lseek(0, SEEK.SET)

        [(local_sock, remote_sock)] = await self.remote_stdtask.make_connections(1)

        local_child = await start_cat(self.stdtask, cat, local_file, local_sock)
        await local_sock.close()

        remote_child = await start_cat(self.remote_stdtask, cat, remote_sock, remote_file)
        await remote_sock.close()

        await local_child.check()
        await remote_child.check()

        await remote_file.lseek(0, SEEK.SET)
        read, _ = await remote_file.read(await self.remote_ram.malloc_type(Bytes, len(data)))
        self.assertEqual(await read.read(), data)

    async def test_sigmask_bug(self) -> None:
        thread = await self.remote_stdtask.fork()
        await thread.stdtask.unshare_files(going_to_exec=True)
        await rsyscall.io.do_cloexec_except(
            thread.stdtask.task, set([fd.near for fd in thread.stdtask.task.base.fd_handles]))
        await self.remote_task.sigprocmask((HowSIG.SETMASK,
                                            await self.remote_ram.to_pointer(Sigset())),
                                           await self.remote_ram.malloc_struct(Sigset))
        await self.remote_task.read_oldset_and_check()
