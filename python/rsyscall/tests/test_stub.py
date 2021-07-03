from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.tasks.stub import *

import rsyscall.nix as nix
from rsyscall import local_thread

from rsyscall.tests.utils import do_async_things
from rsyscall.command import Command
from rsyscall.stdlib import mkdtemp

import os

class TestStub(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.local = local_thread
        self.tmpdir = await mkdtemp(self.local, "test_stub")
        # make sure that this name doesn't collide with shell builtins
        # so it can be run from the shell in test_read_stdin
        self.stub_name = "dummy_stub"
        self.server = await StubServer.make(self.local, self.tmpdir, self.stub_name)
        self.thread = await self.local.clone()

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_exit(self) -> None:
        command = Command(self.tmpdir/self.stub_name, [self.stub_name], {})
        child = await self.thread.exec(command)
        self.nursery.start_soon(child.check)
        argv, new_thread = await self.server.accept()
        await new_thread.exit(0)

    async def test_async(self) -> None:
        command = Command(self.tmpdir/self.stub_name, [self.stub_name], {})
        child = await self.thread.exec(command)
        self.nursery.start_soon(child.check)
        argv, new_thread = await self.server.accept()
        await do_async_things(self, new_thread.epoller, new_thread)

    async def test_read_stdin(self) -> None:
        data_in = "hello"
        command = self.thread.environ.sh.args("-c", f"printf {data_in} | {self.stub_name}").env(PATH=os.fsdecode(self.tmpdir))
        child = await self.thread.exec(command)
        self.nursery.start_soon(child.check)
        argv, new_thread = await self.server.accept()
        valid, _ = await new_thread.stdin.read(
            await new_thread.ram.malloc(bytes, len(data_in)))
        self.assertEqual(data_in, (await valid.read()).decode())
    
