from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store
from rsyscall.tasks.stub import *

import rsyscall.nix as nix
import rsyscall.tasks.local as local

from rsyscall.tests.utils import do_async_things
from rsyscall.io import Command
from rsyscall.struct import Bytes

import os

class TestStub(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = local.thread
        self.store = nix.local_store
        self.tmpdir = await self.stdtask.mkdtemp("test_stub")
        self.path = self.tmpdir.path
        # make sure that this name doesn't collide with shell builtins
        # so it can be run from the shell in test_read_stdin
        self.stub_name = "dummy_stub"
        self.server = await StubServer.make(self.stdtask, self.store, self.path, self.stub_name)
        self.thread = await self.stdtask.fork()

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_exit(self) -> None:
        command = Command(self.path/self.stub_name, [self.stub_name], {})
        child = await self.thread.exec(command)
        argv, new_stdtask = await self.server.accept()
        await new_stdtask.exit(0)

    async def test_async(self) -> None:
        command = Command(self.path/self.stub_name, [self.stub_name], {})
        child = await self.thread.exec(command)
        argv, new_stdtask = await self.server.accept()
        await do_async_things(self, new_stdtask.epoller, new_stdtask)

    async def test_read_stdin(self) -> None:
        data_in = "hello"
        command = self.stdtask.environ.sh.args("-c", f"printf {data_in} | {self.stub_name}").env(PATH=os.fsdecode(self.path))
        child = await self.thread.exec(command)
        argv, new_stdtask = await self.server.accept()
        valid, _ = await new_stdtask.stdin.read(
            await new_stdtask.ram.malloc_type(Bytes, len(data_in)))
        self.assertEqual(data_in, (await valid.read()).decode())
    
