from __future__ import annotations
import unittest

from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
from rsyscall.tasks.exec import *

import rsyscall.tasks.local as local

from rsyscall.thread import do_cloexec_except

from rsyscall.tests.utils import do_async_things
from rsyscall.fcntl import O
from rsyscall.unistd import Pipe

class TestMisc(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local.thread
        self.store = local_store
        self.executables = await RsyscallServerExecutable.from_store(self.store)
        self.thr = await self.local.fork()

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_do_cloexec_except(self) -> None:
        # do_cloexec_except breaks trio when run locally
        await rsyscall_exec(self.local, self.thr, self.executables)

        pipe = await (await self.thr.task.pipe(await self.thr.ram.malloc(Pipe))).read()
        close_set = set([fd.near for fd in self.thr.task.fd_handles])
        close_set.remove(pipe.read.near)
        await do_cloexec_except(self.thr, close_set)

        data = await self.thr.ram.ptr(b"foo")
        with self.assertRaises(OSError):
            # this side was closed due to being cloexec
            await pipe.read.read(data)
        with self.assertRaises(BrokenPipeError):
            # this side is still open, but gets EPIPE
            await pipe.write.write(data)
