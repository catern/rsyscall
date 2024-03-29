from __future__ import annotations
from rsyscall import AsyncChildPid, Process
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.tasks.persistent import *
from rsyscall.tasks.ssh import make_local_ssh, SSHHost
from rsyscall.near.sysif import SyscallHangup
from rsyscall.tests.utils import assert_process_works
from rsyscall.sched import CLONE
from rsyscall.signal import SIG
from rsyscall.stdlib import mkdtemp
import unittest

class TestPersistent(TrioTestCase):
    host: SSHHost
    local_child: AsyncChildPid
    remote: Process

    @classmethod
    async def asyncSetUpClass(cls) -> None:
        cls.host = await make_local_ssh(cls.process)
        cls.local_child, cls.remote = await cls.host.ssh(cls.process)

    @classmethod
    async def asyncTearDownClass(cls) -> None:
        await cls.local_child.kill()

    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(self.process, "test_stub")
        self.sock_path = self.tmpdir/"persist.sock"

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_reconnect_exit(self) -> None:
        per_thr = await clone_persistent(self.process, self.sock_path)
        await assert_process_works(self, per_thr)
        await per_thr.reconnect(self.process)
        await assert_process_works(self, per_thr)
        await per_thr.exit(0)

    async def test_exit_reconnect(self) -> None:
        process = await self.process.fork()
        per_thr = await clone_persistent(self.process, self.sock_path)
        await per_thr.prep_for_reconnect()
        await per_thr.exit(0)
        # when we try to reconnect, we'll fail
        with self.assertRaises(ConnectionRefusedError):
            await per_thr.reconnect(self.process)

    async def test_nest_exit(self) -> None:
        per_thr = await clone_persistent(self.process, self.sock_path)
        process = await per_thr.clone(CLONE.FILES)
        await per_thr.reconnect(self.process)
        await assert_process_works(self, process)
        await process.exit(0)

    async def test_nest_unshare_files_exit(self) -> None:
        per_thr = await clone_persistent(self.process, self.sock_path)
        process = await per_thr.fork()
        await per_thr.reconnect(self.process)
        await assert_process_works(self, process)
        await process.exit(0)

    async def test_ssh_same(self) -> None:
        per_thr = await clone_persistent(self.remote, self.sock_path)
        await per_thr.reconnect(self.remote)
        await assert_process_works(self, per_thr)
        await per_thr.exit(0)

    async def test_ssh_new(self) -> None:
        "Start the persistent process from one ssh process, then reconnect to it from a new ssh process."
        per_thr = await clone_persistent(self.remote, self.sock_path)

        local_child, new_remote = await self.host.ssh(self.process)
        await per_thr.reconnect(new_remote)
        await assert_process_works(self, per_thr)

        await per_thr.exit(0)

    async def test_no_make_persistent(self) -> None:
        pidns_thr = await self.process.clone(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.fork()
        await sacr_thr.task.setpgid()
        per_thr = await clone_persistent(sacr_thr, self.sock_path)
        # kill sacr_thr's process group to kill per_thr too
        await sacr_thr.pid.killpg(SIG.KILL)
        # the persistent process is dead, we can't reconnect to it
        with self.assertRaises(BaseException): # type: ignore
            await per_thr.reconnect(self.process)

    async def test_make_persistent(self) -> None:
        # use a pidns so that the persistent task will be killed after all
        pidns_thr = await self.process.clone(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.fork()
        await sacr_thr.task.setpgid()
        per_thr = await clone_persistent(sacr_thr, self.sock_path)
        # make the persistent process, actually persistent.
        await per_thr.make_persistent()
        # kill sacr_thr's process group
        await sacr_thr.pid.killpg(SIG.KILL)
        # the persistent process is still around!
        await per_thr.reconnect(self.process)
        await assert_process_works(self, per_thr)
        await per_thr.exit(0)
