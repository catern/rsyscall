from __future__ import annotations
import unittest

from rsyscall.trio_test_case import TrioTestCase
from rsyscall.nix import local_store

import rsyscall.tasks.local as local

from rsyscall.tests.test_io import do_async_things
from rsyscall.fcntl import O
from rsyscall.unistd import SEEK
from rsyscall.struct import Bytes

class TestFS(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.store = local_store
        self.tmpdir = await self.thr.mkdtemp()
        self.path = self.tmpdir.path

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_copy(self) -> None:
        source_file = await self.thr.task.open(await self.thr.ram.to_pointer(self.path/"source"), O.RDWR|O.CREAT)
        data = b'hello world'
        buf: Pointer[Bytes] = await self.thr.ram.to_pointer(Bytes(data))
        valid, rest = await source_file.write(buf)
        buf = valid + rest
        await source_file.lseek(0, SEEK.SET)
        dest_file = await self.thr.task.open(await self.thr.ram.to_pointer(self.path/"dest"), O.RDWR|O.CREAT)

        thread = await self.thr.fork()
        cat = await self.thr.environ.which("cat")
        await thread.unshare_files_and_replace({
            thread.stdin: source_file,
            thread.stdout: dest_file,
        })
        child_process = await thread.exec(cat)
        await child_process.check()

        await dest_file.lseek(0, SEEK.SET)
        self.assertEqual(await (await dest_file.read(buf))[0].read(), data)
