from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sys.socket import AF, SOCK, Socketpair
from rsyscall.unistd import Pipe
from rsyscall.fcntl import O

from rsyscall.sched import CLONE
from rsyscall.tests.utils import assert_process_works

class TestPidns(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.init = await self.process.clone(CLONE.NEWUSER|CLONE.NEWPID|CLONE.FILES)

    async def test_cat(self) -> None:
        cat = await self.process.environ.which('cat')
        pair = await (await self.process.task.socketpair(
            AF.UNIX, SOCK.STREAM, 0, await self.process.task.malloc(Socketpair))).read()
        child = await self.init.fork()
        child_side = child.task.inherit_fd(pair.first)
        # close in parent so we'll get EOF on other side when cat dies
        await pair.first.close()
        await child_side.dup2(child.stdin)
        await child_side.dup2(child.stdout)
        child_pid = await child.exec(cat)
        await self.init.exit(0)
        # cat dies, get EOF on socket
        read, _ = await pair.second.read(await self.process.task.malloc(bytes, 16))
        self.assertEqual(read.size(), 0)

    async def test_sleep(self) -> None:
        pipe = await (await self.process.task.pipe(await self.process.task.malloc(Pipe))).read()
        child = await self.init.fork()
        child_fd = child.task.inherit_fd(pipe.write)
        await pipe.write.close()
        await child_fd.disable_cloexec()
        child_pid = await child.exec(child.environ.sh.args('-c', '{ sleep inf & } &'))
        await child_pid.check()
        await self.init.exit(0)
        read, _ = await pipe.read.read(await self.process.task.malloc(bytes, 1))
        self.assertEqual(read.size(), 0)
