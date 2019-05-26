from __future__ import annotations
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
import rsyscall.tasks.local as local
from rsyscall.tasks.persistent import *
from rsyscall.tasks.ssh import make_local_ssh
from rsyscall.tasks.exceptions import RsyscallHangup
from rsyscall.tests.utils import assert_thread_works
from rsyscall.sched import CLONE
from rsyscall.signal import SIG

class TestPersistent(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thread = local.thread
        self.store = local_store
        self.tmpdir = await self.thread.mkdtemp("test_stub")
        self.sock_path = self.tmpdir.path/"persist.sock"

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_reconnect_exit(self) -> None:
        per_thr, connection = await fork_persistent(self.thread, self.sock_path)
        await assert_thread_works(self, per_thr)
        await connection.reconnect(self.thread)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)

    async def test_exit_reconnect(self) -> None:
        thread = await self.thread.fork()
        per_thr, connection = await fork_persistent(self.thread, self.sock_path)
        await per_thr.exit(0)
        # when we try to reconnect, we'll fail
        with self.assertRaises(RsyscallHangup):
            await connection.reconnect(self.thread)

    async def test_nest_exit(self) -> None:
        per_thr, connection = await fork_persistent(self.thread, self.sock_path)
        thread = await per_thr.fork()
        async with thread:
            await connection.reconnect(self.thread)
            await assert_thread_works(self, thread)
            await thread.exit(0)

    async def test_ssh_same(self) -> None:
        host = await make_local_ssh(self.thread, self.store)
        local_child, remote_thread = await host.ssh(self.thread)
        per_thr, connection = await fork_persistent(remote_thread, self.sock_path)
        await connection.reconnect(remote_thread)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)

    async def test_ssh_new(self) -> None:
        "Start the persistent thread from one ssh thread, then reconnect to it from a new ssh thread."
        host = await make_local_ssh(self.thread, self.store)
        local_child, remote_thread = await host.ssh(self.thread)
        per_thr, connection = await fork_persistent(remote_thread, self.sock_path)

        local_child, remote_thread = await host.ssh(self.thread)
        await connection.reconnect(remote_thread)
        await assert_thread_works(self, per_thr)

        await per_thr.exit(0)

    async def test_no_make_persistent(self) -> None:
        pidns_thr = await self.thread.fork(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.fork()
        await sacr_thr.task.setpgid()
        per_thr, connection = await fork_persistent(sacr_thr, self.sock_path)
        # kill sacr_thr's process group to kill per_thr too
        await sacr_thr.task.process.killpg(SIG.KILL)
        # the persistent thread is dead, we can't reconnect to it
        with self.assertRaises(BaseException): # type: ignore
            await connection.reconnect(self.thread)

    async def test_make_persistent(self) -> None:
        # use a pidns so that the persistent task will be killed after all
        pidns_thr = await self.thread.fork(CLONE.NEWUSER|CLONE.NEWPID)
        sacr_thr = await pidns_thr.fork()
        await sacr_thr.task.setpgid()
        per_thr, connection = await fork_persistent(sacr_thr, self.sock_path)
        # make the persistent thread, actually persistent.
        await connection.make_persistent()
        # kill sacr_thr's process group
        await sacr_thr.task.process.killpg(SIG.KILL)
        # the persistent thread is still around!
        await connection.reconnect(self.thread)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)
