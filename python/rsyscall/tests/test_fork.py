from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.tests.utils import do_async_things
from rsyscall.epoller import Epoller
from rsyscall.monitor import SignalQueue

from rsyscall.signal import Signals, Sigset
from rsyscall.sys.signalfd import SignalfdSiginfo
from rsyscall.sched import UnCLONE
from rsyscall.sys.wait import W

import trio

class TestFork(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.thr = await self.local.fork()

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_exit(self) -> None:
        await self.thr.exit(0)

    async def test_nest_exit(self) -> None:
        thread = await self.thr.fork()
        async with thread:
            await thread.exit(0)

    async def test_async(self) -> None:
        epoller = await Epoller.make_root(self.thr.ram, self.thr.task)
        await do_async_things(self, epoller, self.thr)

    async def test_nest_async(self) -> None:
        thread = await self.thr.fork()
        async with thread:
            epoller = await Epoller.make_root(thread.ram, thread.task)
            await do_async_things(self, epoller, thread)

    async def test_unshare_async(self) -> None:
        await self.thr.unshare_files()
        thread = await self.thr.fork()
        async with thread:
            epoller = await Epoller.make_root(thread.ram, thread.task)
            await thread.unshare_files()
            await do_async_things(self, epoller, thread)

    async def test_exec(self) -> None:
        child = await self.thr.exec(self.thr.environ.sh.args('-c', 'true'))
        await child.check()

    async def test_mkdtemp(self) -> None:
        async with (await self.thr.mkdtemp()):
            pass

    async def test_signal_queue(self) -> None:
        # have to use an epoller for this specific task
        epoller = await Epoller.make_root(self.thr.ram, self.thr.task)
        sigqueue = await SignalQueue.make(self.thr.ram, self.thr.task, epoller, Sigset({Signals.SIGINT}))
        await self.thr.task.process.kill(Signals.SIGINT)
        buf = await self.thr.ram.malloc_struct(SignalfdSiginfo)
        sigdata = await sigqueue.read(buf)
        self.assertEqual((await sigdata.read()).signo, Signals.SIGINT)

    async def test_newpid(self) -> None:
        sleep = await self.local.environ.which('sleep')
        print("er")
        # ah we need to take over monitoring now that we did NEWPID.
        await self.thr.unshare(UnCLONE.NEWUSER|UnCLONE.NEWPID)
        print("er 2")
        # hmm how do we set up the newuser
        # well it's set up for me, I guess it's fine
        init = await self.thr.fork()
        print("um")
        # dumb-init or what?
        # oh, just do nothing! nice.
        # and... maybe fork-bomb?
        # sure, sure.
        child = await self.thr.fork()
        print("uder")
        # child_process = await child.exec(child.environ.sh.args('-c', '{ sleep inf & } &'))
        child_process = await child.exec(sleep.args('inf'))
        await trio.sleep(1)
        await init.exit(0)
        print("hi")
        await child_process.waitpid(W.EXITED)
