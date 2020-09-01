from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.tests.utils import do_async_things
from rsyscall.epoller import Epoller
from rsyscall.monitor import AsyncSignalfd

from rsyscall.sched import CLONE
from rsyscall.signal import SIG, Sigset
from rsyscall.sys.signalfd import SignalfdSiginfo

class TestClone(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = await local.thread.clone(CLONE.FILES)

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_exit(self) -> None:
        await self.thr.exit(0)

    async def test_nest_exit(self) -> None:
        thread = await self.thr.clone(CLONE.FILES)
        async with thread:
            await thread.exit(0)

    async def test_two_children_exec(self) -> None:
        """Start two child and exec in each of them.

        This test would (sometimes) catch a race condition we had where waitpid
        on one child would consume the SIGCHLD for another child, and our logic
        to eagerly call waitid was wrong, so waitpid on the other child would
        block forever.

        """
        thr2 = await local.thread.clone()
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
        async with thread:
            epoller = await Epoller.make_root(thread.ram, thread.task)
            await do_async_things(self, epoller, thread)

    async def test_unshare_async(self) -> None:
        await self.thr.unshare(CLONE.FILES)
        thread = await self.thr.clone(CLONE.FILES)
        async with thread:
            epoller = await Epoller.make_root(thread.ram, thread.task)
            await thread.unshare(CLONE.FILES)
            await do_async_things(self, epoller, thread)

    async def test_exec(self) -> None:
        child = await self.thr.exec(self.thr.environ.sh.args('-c', 'true'))
        await child.check()

    async def test_nest_exec(self) -> None:
        child = await self.thr.clone()
        grandchild = await child.clone()
        cmd = self.thr.environ.sh.args('-c', 'true')
        await (await child.exec(cmd)).check()
        await (await grandchild.exec(cmd)).check()

    async def test_mkdtemp(self) -> None:
        async with (await self.thr.mkdtemp()):
            pass

    async def test_signal_queue(self) -> None:
        # have to use an epoller for this specific task
        epoller = await Epoller.make_root(self.thr.ram, self.thr.task)
        sigfd = await AsyncSignalfd.make(self.thr.ram, self.thr.task, epoller, Sigset({SIG.INT}))
        await self.thr.process.kill(SIG.INT)
        buf = await self.thr.ram.malloc(SignalfdSiginfo)
        sigdata, _ = await sigfd.afd.read(buf)
        self.assertEqual((await sigdata.read()).signo, SIG.INT)

class TestCloneUnshareFiles(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.thr = await self.local.clone()

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_nest_async(self) -> None:
        thread = await self.thr.clone()
        async with thread:
            epoller = await Epoller.make_root(thread.ram, thread.task)
            await do_async_things(self, epoller, thread)
