from __future__ import annotations
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.tasks.persistent import *
from rsyscall.tasks.ssh import make_local_ssh
from rsyscall.near.sysif import SyscallHangup
from rsyscall.tests.utils import assert_process_works
from rsyscall.sched import CLONE
from rsyscall.signal import SIG
from rsyscall.stdlib import mkdtemp
import unittest

class TestPersistent(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(self.thr, "test_stub")
        self.sock_path = self.tmpdir/"persist.sock"

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_reconnect_exit(self) -> None:
        per_thr = await clone_persistent(self.thr, self.sock_path)
        await assert_process_works(self, per_thr)
        await per_thr.reconnect(self.thr)
        await assert_process_works(self, per_thr)
        await per_thr.exit(0)

    async def test_exit_reconnect(self) -> None:
        process = await self.thr.clone()
        per_thr = await clone_persistent(self.thr, self.sock_path)
        await per_thr.prep_for_reconnect()
        await per_thr.exit(0)
        # when we try to reconnect, we'll fail
        with self.assertRaises(ConnectionRefusedError):
            await per_thr.reconnect(self.thr)

    async def test_nest_exit(self) -> None:
        per_thr = await clone_persistent(self.thr, self.sock_path)
        process = await per_thr.clone(CLONE.FILES)
        await per_thr.reconnect(self.thr)
        await assert_process_works(self, process)
        await process.exit(0)

    async def test_nest_unshare_files_exit(self) -> None:
        per_thr = await clone_persistent(self.thr, self.sock_path)
        process = await per_thr.clone()
        await per_thr.reconnect(self.thr)
        await assert_process_works(self, process)
        await process.exit(0)

    async def test_ssh_same(self) -> None:
        host = await make_local_ssh(self.thr)
        local_child, remote_process = await host.ssh(self.thr)
        per_thr = await clone_persistent(remote_process, self.sock_path)
        await per_thr.reconnect(remote_process)
        await assert_process_works(self, per_thr)
        await per_thr.exit(0)

    async def test_ssh_new(self) -> None:
        "Start the persistent process from one ssh process, then reconnect to it from a new ssh process."
        host = await make_local_ssh(self.thr)
        local_child, remote_process = await host.ssh(self.thr)
        per_thr = await clone_persistent(remote_process, self.sock_path)

        local_child, remote_process = await host.ssh(self.thr)
        await per_thr.reconnect(remote_process)
        await assert_process_works(self, per_thr)

        await per_thr.exit(0)

    async def test_no_make_persistent(self) -> None:
        pidns_thr = await self.thr.clone(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.clone()
        await sacr_thr.task.setpgid()
        per_thr = await clone_persistent(sacr_thr, self.sock_path)
        # kill sacr_thr's process group to kill per_thr too
        await sacr_thr.pid.killpg(SIG.KILL)
        # the persistent process is dead, we can't reconnect to it
        with self.assertRaises(BaseException): # type: ignore
            await per_thr.reconnect(self.thr)

    async def test_make_persistent(self) -> None:
        # use a pidns so that the persistent task will be killed after all
        pidns_thr = await self.thr.clone(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.clone()
        await sacr_thr.task.setpgid()
        per_thr = await clone_persistent(sacr_thr, self.sock_path)
        # make the persistent process, actually persistent.
        await per_thr.make_persistent()
        # kill sacr_thr's process group
        await sacr_thr.pid.killpg(SIG.KILL)
        # the persistent process is still around!
        await per_thr.reconnect(self.thr)
        await assert_process_works(self, per_thr)
        await per_thr.exit(0)
