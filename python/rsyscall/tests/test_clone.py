from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.tests.utils import do_async_things
from rsyscall.epoller import Epoller
from rsyscall.monitor import AsyncSignalfd

from rsyscall.sched import CLONE
from rsyscall.signal import SIG, Sigset
from rsyscall.stdlib import mkdtemp
from rsyscall.sys.signalfd import SignalfdSiginfo
from rsyscall.sys.wait import CalledProcessError

class TestClone(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.child = await self.process.clone(CLONE.FILES)

    async def test_exit(self) -> None:
        await self.child.exit(0)

    async def test_nest_exit(self) -> None:
        process = await self.child.clone(CLONE.FILES)
        await process.exit(0)

    async def test_nest_multiple(self) -> None:
        for i in range(5):
            child = await self.child.fork()
            await do_async_things(self, child.epoller, child)
            await child.exit(0)

    async def test_two_children_exec(self) -> None:
        """Start two child and exec in each of them.

        This test would (sometimes) catch a race condition we had where waitpid
        on one child would consume the SIGCHLD for another child, and our logic
        to eagerly call waitid was wrong, so waitpid on the other child would
        block forever.

        """
        thr2 = await self.process.fork()
        cmd = self.child.environ.sh.args('-c', 'true')
        child1 = await self.child.exec(cmd)
        child2 = await thr2.exec(cmd)
        await child1.check()
        await child2.check()

    async def test_async(self) -> None:
        epoller = await Epoller.make_root(self.child.ram, self.child.task)
        await do_async_things(self, epoller, self.child)

    async def test_nest_async(self) -> None:
        process = await self.child.clone(CLONE.FILES)
        epoller = await Epoller.make_root(process.ram, process.task)
        await do_async_things(self, epoller, process)
        await process.exit(0)

    async def test_unshare_async(self) -> None:
        await self.child.unshare(CLONE.FILES)
        process = await self.child.clone(CLONE.FILES)
        epoller = await Epoller.make_root(process.ram, process.task)
        await process.unshare(CLONE.FILES)
        await do_async_things(self, epoller, process)
        await process.exit(0)

    async def test_exec(self) -> None:
        child = await self.child.exec(self.child.environ.sh.args('-c', 'false'))
        with self.assertRaises(CalledProcessError):
            await child.check()

    async def test_check_in_nursery(self) -> None:
        "We broke this with some concurrency refactoring once"
        child = await self.child.exec(self.child.environ.sh.args('-c', 'sleep inf'))
        self.nursery.start_soon(child.check)

    async def test_nest_exec(self) -> None:
        child = await self.child.fork()
        grandchild = await child.fork()
        cmd = self.child.environ.sh.args('-c', 'true')
        await (await child.exec(cmd)).check()
        await (await grandchild.exec(cmd)).check()

    async def test_mkdtemp(self) -> None:
        async with (await mkdtemp(self.child)):
            pass

    async def test_signal_queue(self) -> None:
        epoller = await Epoller.make_root(self.child.ram, self.child.task)
        sigfd = await AsyncSignalfd.make(self.child.ram, self.child.task, epoller, Sigset({SIG.INT}))
        sigevent = sigfd.next_signal
        await self.child.pid.kill(SIG.INT)
        await sigevent.wait()

class TestCloneUnshareFiles(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.child = await self.process.fork()

    async def asyncTearDown(self) -> None:
        await self.child.exit(0)

    async def test_nest_async(self) -> None:
        process = await self.child.fork()
        epoller = await Epoller.make_root(process.ram, process.task)
        await do_async_things(self, epoller, process)
        await process.exit(0)
