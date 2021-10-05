from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
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
        self.thr = await local_thread.clone(CLONE.FILES)

    async def test_exit(self) -> None:
        await self.thr.exit(0)

    async def test_nest_exit(self) -> None:
        thread = await self.thr.clone(CLONE.FILES)
        await thread.exit(0)

    async def test_nest_multiple(self) -> None:
        for i in range(5):
            child = await self.thr.clone()
            await do_async_things(self, child.epoller, child)
            await child.exit(0)

    async def test_two_children_exec(self) -> None:
        """Start two child and exec in each of them.

        This test would (sometimes) catch a race condition we had where waitpid
        on one child would consume the SIGCHLD for another child, and our logic
        to eagerly call waitid was wrong, so waitpid on the other child would
        block forever.

        """
        thr2 = await local_thread.clone()
        cmd = self.thr.environ.sh.args('-c', 'true')
        child1 = await self.thr.exec(cmd)
        child2 = await thr2.exec(cmd)
        await child1.check()
        await child2.check()

    async def test_async(self) -> None:
        epoller = await Epoller.make_root(self.thr.ram, self.thr.task)
        await do_async_things(self, epoller, self.thr)

    async def test_nest_async(self) -> None:
        thread = await self.thr.clone(CLONE.FILES)
        epoller = await Epoller.make_root(thread.ram, thread.task)
        await do_async_things(self, epoller, thread)
        await thread.exit(0)

    async def test_unshare_async(self) -> None:
        await self.thr.unshare(CLONE.FILES)
        thread = await self.thr.clone(CLONE.FILES)
        epoller = await Epoller.make_root(thread.ram, thread.task)
        await thread.unshare(CLONE.FILES)
        await do_async_things(self, epoller, thread)
        await thread.exit(0)

    async def test_exec(self) -> None:
        child = await self.thr.exec(self.thr.environ.sh.args('-c', 'false'))
        with self.assertRaises(CalledProcessError):
            await child.check()

    async def test_check_in_nursery(self) -> None:
        "We broke this with some concurrency refactoring once"
        child = await self.thr.exec(self.thr.environ.sh.args('-c', 'sleep inf'))
        self.nursery.start_soon(child.check)

    async def test_nest_exec(self) -> None:
        child = await self.thr.clone()
        grandchild = await child.clone()
        cmd = self.thr.environ.sh.args('-c', 'true')
        await (await child.exec(cmd)).check()
        await (await grandchild.exec(cmd)).check()

    async def test_mkdtemp(self) -> None:
        async with (await mkdtemp(self.thr)):
            pass

    async def test_signal_queue(self) -> None:
        epoller = await Epoller.make_root(self.thr.ram, self.thr.task)
        sigfd = await AsyncSignalfd.make(self.thr.ram, self.thr.task, epoller, Sigset({SIG.INT}))
        sigevent = sigfd.next_signal
        await self.thr.process.kill(SIG.INT)
        await sigevent.wait()

class TestCloneUnshareFiles(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.thr = await self.local.clone()

    async def asyncTearDown(self) -> None:
        await self.thr.exit(0)

    async def test_nest_async(self) -> None:
        thread = await self.thr.clone()
        epoller = await Epoller.make_root(thread.ram, thread.task)
        await do_async_things(self, epoller, thread)
        await thread.exit(0)
