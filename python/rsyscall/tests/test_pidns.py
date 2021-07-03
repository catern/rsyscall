from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.sys.socket import AF, SOCK, Socketpair
from rsyscall.unistd import Pipe
from rsyscall.fcntl import O

from rsyscall.sched import CLONE
from rsyscall.tests.utils import assert_thread_works

class TestPidns(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.init = await self.local.clone(CLONE.NEWUSER|CLONE.NEWPID|CLONE.FILES)

    async def test_cat(self) -> None:
        cat = await self.local.environ.which('cat')
        pair = await (await self.local.task.socketpair(
            AF.UNIX, SOCK.STREAM, 0, await self.local.ram.malloc(Socketpair))).read()
        child = await self.init.clone()
        child_side = child.task.inherit_fd(pair.first)
        # close in parent so we'll get EOF on other side when cat dies
        await pair.first.close()
        await child_side.dup2(child.stdin)
        await child_side.dup2(child.stdout)
        child_process = await child.exec(cat)
        await self.init.exit(0)
        # cat dies, get EOF on socket
        read, _ = await pair.second.read(await self.local.ram.malloc(bytes, 16))
        self.assertEqual(read.size(), 0)

    async def test_sleep(self) -> None:
        pipe = await (await self.local.task.pipe(await self.local.ram.malloc(Pipe))).read()
        child = await self.init.clone()
        child_fd = child.task.inherit_fd(pipe.write)
        await pipe.write.close()
        await child_fd.disable_cloexec()
        child_process = await child.exec(child.environ.sh.args('-c', '{ sleep inf & } &'))
        await child_process.check()
        await self.init.exit(0)
        read, _ = await pipe.read.read(await self.local.ram.malloc(bytes, 1))
        self.assertEqual(read.size(), 0)
