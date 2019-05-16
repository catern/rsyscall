from __future__ import annotations
import unittest

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.io
from rsyscall.nix import local_store
import rsyscall.tasks.local as local
from rsyscall.tasks.persistent import *
from rsyscall.tasks.ssh import make_local_ssh

import logging
# logging.basicConfig(level=logging.DEBUG)

class TestPersistent(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = local.stdtask
        self.store = local_store
        self.tmpdir = await self.stdtask.mkdtemp("test_stub")
        self.sock_path = self.tmpdir.path/"persist.sock"
        self.task = self.stdtask.task.base
        self.ram = self.stdtask.ram

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_exit(self) -> None:
        per_stdtask, connection = await fork_persistent(self.stdtask, self.sock_path)
        await connection.reconnect(self.stdtask)
        await per_stdtask.unshare_files()
        await per_stdtask.exit(0)

    async def test_nest_exit(self) -> None:
        per_stdtask, connection = await fork_persistent(self.stdtask, self.sock_path)
        thread = await per_stdtask.fork()
        async with thread:
            await connection.reconnect(self.stdtask)
            await thread.exit(0)

    async def test_ssh_same(self) -> None:
        host = await make_local_ssh(self.stdtask, self.store)
        local_child, remote_stdtask = await host.ssh(self.stdtask)
        per_stdtask, connection = await fork_persistent(remote_stdtask, self.sock_path)
        await per_stdtask.unshare_files()
        await connection.reconnect(remote_stdtask)
        await per_stdtask.exit(0)

    async def test_ssh_new(self) -> None:
        "Start the persistent thread from one ssh thread, then reconnect to it from a new ssh thread."
        host = await make_local_ssh(self.stdtask, self.store)
        local_child, remote_stdtask = await host.ssh(self.stdtask)
        per_stdtask, connection = await fork_persistent(remote_stdtask, self.sock_path)

        await per_stdtask.unshare_files()

        local_child, remote_stdtask = await host.ssh(self.stdtask)
        await connection.reconnect(remote_stdtask)

        await per_stdtask.exit(0)

    async def test_no_make_persistent(self) -> None:
        pidns_thr = await self.stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)

        sacr_thr = await pidns_thr.fork()

        per_thr, connection = await fork_persistent(sacr_thr, self.sock_path)
        # TODO argh, we need this because otherwise the listening socket is still around in our fd space.
        await per_thr.unshare_files()
        # exit sacr_thr, and per_thr will be killed by PDEATHSIG, like a normal thread
        await sacr_thr.exit(0)

        # the persistent thread is dead, we can't reconnect to it
        with self.assertRaises(ConnectionRefusedError):
            await connection.reconnect(self.stdtask)

    @unittest.skip("not working right now")
    async def test_make_persistent(self) -> None:
        # use a pidns so that the persistent task will be killed after all
        pidns_thr = await self.stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)

        sacr_thr = await pidns_thr.fork()

        per_thr, connection = await fork_persistent(sacr_thr, self.sock_path)
        await connection.make_persistent()
        # TODO argh, we need this because otherwise the listening socket is still around in our fd space.
        await per_thr.unshare_files()
        # exit sacr_thr, and per_thr won't be killed
        await sacr_thr.exit(0)

        # the persistent thread is still around!
        await connection.reconnect(self.stdtask)
