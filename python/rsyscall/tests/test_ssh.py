from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.io
from rsyscall.io import local_stdtask
from rsyscall.nix import local_store
from rsyscall.misc import bash_nixdep, coreutils_nixdep
from rsyscall.struct import Bytes
from rsyscall.tasks.ssh import *

from rsyscall.unistd import SEEK

import rsyscall.handle as handle
from rsyscall.io import StandardTask, Command, ChildProcess

async def start_cat(stdtask: StandardTask, cat: Command,
                    stdin: handle.FileDescriptor, stdout: handle.FileDescriptor) -> ChildProcess:
    thread = await stdtask.fork()
    await thread.stdtask.unshare_files_and_replace({
        thread.stdtask.stdin.handle: stdin,
        thread.stdtask.stdout.handle: stdout,
    }, going_to_exec=True)
    child = await thread.exec(cat)
    return child

class TestSSH(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = local_stdtask
        self.store = local_store
        self.host = await make_local_ssh(self.stdtask, self.store)
        self.local_child, self.remote_stdtask = await self.host.ssh(self.stdtask)

    async def test_read(self) -> None:
        [(local_sock, remote_sock)] = await self.remote_stdtask.make_connections(1)
        data = b"hello world"
        await local_sock.write(data)
        valid, _ = await remote_sock.read(await self.remote_stdtask.task.malloc_type(Bytes, len(data)))
        self.assertEqual(len(data), valid.bytesize())
        self.assertEqual(data, await valid.read())

    async def test_exec(self) -> None:
        bash = await self.store.bin(bash_nixdep, "bash")
        await self.remote_stdtask.run(bash.args('-c', 'true'))

    async def test_copy(self) -> None:
        cat = await self.store.bin(coreutils_nixdep, "cat")

        local_file = await self.stdtask.task.memfd_create("source")
        remote_file = await self.remote_stdtask.task.memfd_create("dest")

        data = b'hello world'
        await local_file.write(data)
        await local_file.handle.lseek(0, SEEK.SET)

        [(local_sock, remote_sock)] = await self.remote_stdtask.make_connections(1)

        local_child = await start_cat(self.stdtask, cat, local_file.handle, local_sock.handle)
        await local_sock.handle.close()

        remote_child = await start_cat(self.remote_stdtask, cat, remote_sock, remote_file.handle)
        await remote_sock.close()

        await local_child.check()
        await remote_child.check()

        await remote_file.handle.lseek(0, SEEK.SET)
        self.assertEqual(await remote_file.read(), data)

    async def test_sigmask_bug(self) -> None:
        thread = await self.remote_stdtask.fork()
        await thread.stdtask.unshare_files(going_to_exec=True)
        await rsyscall.io.do_cloexec_except(
            thread.stdtask.task, thread.stdtask.process,
            [fd.near for fd in thread.stdtask.task.base.fd_handles])
        await thread.stdtask.task.sigmask.setmask(thread.stdtask.task, set())
