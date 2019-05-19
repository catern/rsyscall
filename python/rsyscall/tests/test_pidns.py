from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.tasks.exec import spawn_exec
from rsyscall.sys.socket import AF, SOCK, Socketpair
from rsyscall.struct import Bytes

from rsyscall.nix import local_store
from rsyscall.tests.utils import assert_thread_works

class TestFork(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.store = local_store
        self.init = await self.local.fork(newuser=True, newpid=True, fs=False, sighand=False)

    async def asyncTearDown(self) -> None:
        await self.init.close()

    async def test_spawn(self) -> None:
        await assert_thread_works(self, self.init)
        thread = await spawn_exec(self.init, self.store)
        async with thread:
            await assert_thread_works(self, thread)

    async def test_newpid(self) -> None:
        cat = await self.local.environ.which('cat')
        pair = await (await self.local.task.socketpair(
            AF.UNIX, SOCK.STREAM|SOCK.CLOEXEC, 0, await self.local.ram.malloc(Socketpair))).read()
        child = await self.init.fork()
        await child.unshare_files_and_replace({
            child.stdin: pair.first,
            child.stdout: pair.first,
        })
        await pair.first.close()
        child_process = await child.exec(cat)
        await self.init.close()
        # cat dies, get EOF on socket
        read, _ = await pair.second.read(await self.local.ram.malloc(Bytes, 16))
        self.assertEqual(read.size(), 0)
