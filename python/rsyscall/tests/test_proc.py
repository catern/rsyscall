import unittest
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.sys.socket import AF, SOCK, Socketpair
from rsyscall.unistd import Pipe, SEEK
from rsyscall.fcntl import O
from rsyscall.sys.wait import W, Siginfo

from rsyscall.sched import CLONE
from rsyscall.handle import Process
from rsyscall.tests.utils import assert_thread_works
from rsyscall.signal import SIG

class TestProc(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.init = await self.local.clone(CLONE.NEWUSER|CLONE.NEWPID)
        # set up proc

    async def test_pgid(self) -> None:
        try:
            last_pid = await self.init.task.open(await self.init.ptr("/proc/sys/kernel/ns_last_pid"), O.WRONLY)
        except FileNotFoundError:
            raise unittest.SkipTest("Requires /proc/sys/kernel/ns_last_pid, which requires CONFIG_CHECKPOINT_RESTORE")

        pgldr = await self.init.clone()
        await pgldr.task.setpgid()
        pgflr = await self.init.clone()
        await pgflr.task.setpgid(pgldr.process.process)
        self.assertEqual(int(await pgflr.task.getpgid()), 2)
        await pgldr.exit(0)
        await pgldr.process.waitpid(W.EXITED)
        self.assertIsNotNone(pgldr.process.process.death_state)
        if pgldr.process.process.death_state is None: raise Exception # for mypy
        self.assertEqual(pgldr.process.process.death_state.pid, 2)
        self.assertTrue(pgldr.process.process.death_state.died())
        self.assertEqual(int(await pgflr.task.getpgid()), 2)

        await self.init.spit(last_pid, b"1\n")

        with self.assertRaises(ProcessLookupError):
            await self.init.task._make_process(2).kill(SIG.NONE)
        pg_two = await self.init.clone()
        with self.assertRaises(ProcessLookupError):
            await self.init.task._make_process(2).kill(SIG.NONE)
        # Linux skips right over process 2, even though it's dead, because it's still used by the process group
        self.assertEqual(int(pg_two.task.process.near), 3)
