import unittest
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.sys.socket import AF, SOCK, Socketpair
from rsyscall.unistd import Pipe, SEEK
from rsyscall.fcntl import O
from rsyscall.sys.wait import W, Siginfo

from rsyscall.sched import CLONE
from rsyscall.handle import Pid
from rsyscall.tests.utils import assert_process_works
from rsyscall.signal import SIG

class TestProc(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.init = await self.process.clone(CLONE.NEWUSER|CLONE.NEWPID)
        # set up proc

    async def test_pgid(self) -> None:
        try:
            last_pid = await self.init.task.open(await self.init.ptr("/proc/sys/kernel/ns_last_pid"), O.WRONLY)
        except FileNotFoundError:
            raise unittest.SkipTest("Requires /proc/sys/kernel/ns_last_pid, which requires CONFIG_CHECKPOINT_RESTORE")

        pgldr = await self.init.fork()
        await pgldr.task.setpgid()
        pgflr = await self.init.fork()
        await pgflr.task.setpgid(pgldr.pid.pid)
        self.assertEqual(int(await pgflr.task.getpgid()), 2)
        await pgldr.exit(0)
        await pgldr.pid.waitpid(W.EXITED)
        self.assertIsNotNone(pgldr.pid.pid.death_state)
        if pgldr.pid.pid.death_state is None: raise Exception # for mypy
        self.assertEqual(pgldr.pid.pid.death_state.pid, 2)
        self.assertTrue(pgldr.pid.pid.death_state.died())
        self.assertEqual(int(await pgflr.task.getpgid()), 2)

        await self.init.spit(last_pid, b"1\n")

        with self.assertRaises(ProcessLookupError):
            await self.init.task._make_pid(2).kill(SIG.NONE)
        pg_two = await self.init.fork()
        with self.assertRaises(ProcessLookupError):
            await self.init.task._make_pid(2).kill(SIG.NONE)
        # Linux skips right over process 2, even though it's dead, because it's still used by the process group
        self.assertEqual(int(pg_two.task.pid.near), 3)
