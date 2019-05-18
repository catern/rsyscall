from __future__ import annotations
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
import rsyscall.tasks.local as local
from rsyscall.tasks.persistent import *
from rsyscall.tasks.ssh import make_local_ssh
from rsyscall.tasks.exceptions import RsyscallHangup
from rsyscall.tests.utils import assert_thread_works

class TestPersistent(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = local.stdtask
        self.store = local_store
        self.tmpdir = await self.stdtask.mkdtemp("test_stub")
        self.sock_path = self.tmpdir.path/"persist.sock"

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_reconnect_exit(self) -> None:
        per_thr, connection = await fork_persistent(self.stdtask, self.sock_path)
        await assert_thread_works(self, per_thr)
        await connection.reconnect(self.stdtask)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)

    async def test_exit_reconnect(self) -> None:
        thread = await self.stdtask.fork()
        per_thr, connection = await fork_persistent(self.stdtask, self.sock_path)
        await per_thr.exit(0)
        # when we try to reconnect, we'll fail
        with self.assertRaises(RsyscallHangup):
            await connection.reconnect(self.stdtask)

    async def test_nest_exit(self) -> None:
        per_thr, connection = await fork_persistent(self.stdtask, self.sock_path)
        thread = await per_thr.fork()
        async with thread:
            await connection.reconnect(self.stdtask)
            await assert_thread_works(self, thread)
            await thread.exit(0)

    async def test_ssh_same(self) -> None:
        host = await make_local_ssh(self.stdtask, self.store)
        local_child, remote_stdtask = await host.ssh(self.stdtask)
        per_thr, connection = await fork_persistent(remote_stdtask, self.sock_path)
        await connection.reconnect(remote_stdtask)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)

    async def test_ssh_new(self) -> None:
        "Start the persistent thread from one ssh thread, then reconnect to it from a new ssh thread."
        host = await make_local_ssh(self.stdtask, self.store)
        local_child, remote_stdtask = await host.ssh(self.stdtask)
        per_thr, connection = await fork_persistent(remote_stdtask, self.sock_path)

        local_child, remote_stdtask = await host.ssh(self.stdtask)
        await connection.reconnect(remote_stdtask)
        await assert_thread_works(self, per_thr)

        await per_thr.exit(0)

    async def test_no_make_persistent(self) -> None:
        pidns_thr = await self.stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)
        sacr_thr = await pidns_thr.fork()
        per_thr, connection = await fork_persistent(sacr_thr, self.sock_path)
        # exit sacr_thr, and per_thr will be killed by PDEATHSIG, like a normal thread
        await sacr_thr.exit(0)
        # the persistent thread is dead, we can't reconnect to it
        with self.assertRaises(BaseException): # type: ignore
            await connection.reconnect(self.stdtask)

    async def test_make_persistent(self) -> None:
        # use a pidns so that the persistent task will be killed after all
        pidns_thr = await self.stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)
        sacr_thr = await pidns_thr.fork()
        per_thr, connection = await fork_persistent(sacr_thr, self.sock_path)
        # make the persistent thread, actually persistent.
        await connection.make_persistent()
        # exit sacr_thr, and per_thr won't be killed
        await sacr_thr.exit(0)
        # the persistent thread is still around!
        await connection.reconnect(self.stdtask)
        await assert_thread_works(self, per_thr)
        await per_thr.exit(0)
