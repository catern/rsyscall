import unittest
from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.tasks.exec import spawn_exec
from rsyscall.sys.socket import AF, SOCK, Socketpair
from rsyscall.unistd import Pipe, SEEK
from rsyscall.fcntl import O
from rsyscall.sys.wait import W, Siginfo

from rsyscall.sched import CLONE
from rsyscall.path import Path
from rsyscall.handle import Process
from rsyscall.nix import local_store
from rsyscall.tests.utils import assert_thread_works
from rsyscall.signal import SIG

class TestProc(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.store = local_store
        self.init = await self.local.fork(CLONE.NEWUSER|CLONE.NEWPID)
        # set up proc

    async def test_pgid(self) -> None:
        try:
            last_pid = await self.init.task.open(await self.init.ram.ptr(Path("/proc/sys/kernel/ns_last_pid")), O.WRONLY)
        except FileNotFoundError:
            raise unittest.SkipTest("Requires /proc/sys/kernel/ns_last_pid, which requires CONFIG_CHECKPOINT_RESTORE")

        pgldr = await self.init.fork()
        await pgldr.task.setpgid()
        pgflr = await self.init.fork()
        await pgflr.task.setpgid(pgldr.task.process)
        self.assertEqual(int(await pgflr.task.getpgid()), 2)
        await pgldr.exit(0)
        self.assertEqual(pgldr.task.process.death_event.pid, 2)
        self.assertTrue(pgldr.task.process.death_event.died())
        self.assertEqual(int(await pgflr.task.getpgid()), 2)

        await self.init.spit(last_pid, b"1\n")

        with self.assertRaises(ProcessLookupError):
            await self.init.task._make_process(2).kill(SIG.NONE)
        pg_two = await self.init.fork()
        with self.assertRaises(ProcessLookupError):
            await self.init.task._make_process(2).kill(SIG.NONE)
        # Linux skips right over process 2, even though it's dead, because it's still used by the process group
        self.assertEqual(int(pg_two.task.process.near), 3)
