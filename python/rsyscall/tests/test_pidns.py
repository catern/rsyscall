from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.tasks.exec import spawn_exec
from rsyscall.sys.socket import AF, SOCK, Socketpair
from rsyscall.unistd import Pipe
from rsyscall.fcntl import O

from rsyscall.sched import CLONE
from rsyscall.nix import local_store
from rsyscall.tests.utils import assert_thread_works

class TestPidns(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.store = local_store
        self.init = await self.local.fork(CLONE.NEWUSER|CLONE.NEWPID)

    async def asyncTearDown(self) -> None:
        await self.init.close()

    async def test_spawn(self) -> None:
        await assert_thread_works(self, self.init)
        thread = await spawn_exec(self.init, self.store)
        async with thread:
            await assert_thread_works(self, thread)

    async def test_cat(self) -> None:
        cat = await self.local.environ.which('cat')
        pair = await (await self.local.task.socketpair(
            AF.UNIX, SOCK.STREAM, 0, await self.local.ram.malloc(Socketpair))).read()
        child = await self.init.fork()
        await child.unshare_files_and_replace({
            child.stdin: pair.first,
            child.stdout: pair.first,
        })
        await pair.first.close()
        child_process = await child.exec(cat)
        await self.init.close()
        # cat dies, get EOF on socket
        read, _ = await pair.second.read(await self.local.ram.malloc(bytes, 16))
        self.assertEqual(read.size(), 0)

    async def test_sleep(self) -> None:
        pipe = await (await self.local.task.pipe(await self.local.ram.malloc(Pipe))).read()
        child = await self.init.fork()
        child_fd = pipe.write.move(child.task)
        await child.unshare_files()
        await child_fd.disable_cloexec()
        child_process = await child.exec(child.environ.sh.args('-c', '{ sleep inf & } &'))
        await child_process.check()
        await self.init.close()
        read, _ = await pipe.read.read(await self.local.ram.malloc(bytes, 1))
        self.assertEqual(read.size(), 0)
