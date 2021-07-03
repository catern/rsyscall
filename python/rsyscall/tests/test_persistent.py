from __future__ import annotations
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.tasks.persistent import *
from rsyscall.tasks.ssh import make_local_ssh
from rsyscall.near.sysif import SyscallHangup
from rsyscall.tests.utils import assert_thread_works
from rsyscall.sched import CLONE
from rsyscall.signal import SIG
from rsyscall.stdlib import mkdtemp
import unittest

class TestPersistent(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thread = local_thread
        self.tmpdir = await mkdtemp(self.thread, "test_stub")
        self.sock_path = self.tmpdir/"persist.sock"

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_reconnect_exit(self) -> None:
        per_thr = await clone_persistent(self.thread, self.sock_path)
        await assert_thread_works(self, per_thr)
        await per_thr.reconnect(self.thread)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)

    async def test_exit_reconnect(self) -> None:
        thread = await self.thread.clone()
        per_thr = await clone_persistent(self.thread, self.sock_path)
        await per_thr.prep_for_reconnect()
        await per_thr.exit(0)
        # when we try to reconnect, we'll fail
        with self.assertRaises(ConnectionRefusedError):
            await per_thr.reconnect(self.thread)

    async def test_nest_exit(self) -> None:
        per_thr = await clone_persistent(self.thread, self.sock_path)
        thread = await per_thr.clone(CLONE.FILES)
        await per_thr.reconnect(self.thread)
        await assert_thread_works(self, thread)
        await thread.exit(0)

    async def test_nest_unshare_files_exit(self) -> None:
        per_thr = await clone_persistent(self.thread, self.sock_path)
        thread = await per_thr.clone()
        await per_thr.reconnect(self.thread)
        await assert_thread_works(self, thread)
        await thread.exit(0)

    async def test_ssh_same(self) -> None:
        host = await make_local_ssh(self.thread)
        local_child, remote_thread = await host.ssh(self.thread)
        per_thr = await clone_persistent(remote_thread, self.sock_path)
        await per_thr.reconnect(remote_thread)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)

    async def test_ssh_new(self) -> None:
        "Start the persistent thread from one ssh thread, then reconnect to it from a new ssh thread."
        host = await make_local_ssh(self.thread)
        local_child, remote_thread = await host.ssh(self.thread)
        per_thr = await clone_persistent(remote_thread, self.sock_path)

        local_child, remote_thread = await host.ssh(self.thread)
        await per_thr.reconnect(remote_thread)
        await assert_thread_works(self, per_thr)

        await per_thr.exit(0)

    async def test_no_make_persistent(self) -> None:
        pidns_thr = await self.thread.clone(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.clone()
        await sacr_thr.task.setpgid()
        per_thr = await clone_persistent(sacr_thr, self.sock_path)
        # kill sacr_thr's process group to kill per_thr too
        await sacr_thr.process.killpg(SIG.KILL)
        # the persistent thread is dead, we can't reconnect to it
        with self.assertRaises(BaseException): # type: ignore
            await per_thr.reconnect(self.thread)

    async def test_make_persistent(self) -> None:
        # use a pidns so that the persistent task will be killed after all
        pidns_thr = await self.thread.clone(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.clone()
        await sacr_thr.task.setpgid()
        per_thr = await clone_persistent(sacr_thr, self.sock_path)
        # make the persistent thread, actually persistent.
        await per_thr.make_persistent()
        # kill sacr_thr's process group
        await sacr_thr.process.killpg(SIG.KILL)
        # the persistent thread is still around!
        await per_thr.reconnect(self.thread)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)
