from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local

from rsyscall.sys.inotify import *
from rsyscall.inotify_watch import Inotify
from rsyscall.fcntl import O

class TestInotify(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread
        self.tmpdir = await self.thr.mkdtemp()
        self.path = self.tmpdir.path
        self.ify = await Inotify.make(self.thr)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_create(self) -> None:
        watch = await self.ify.add(self.path, IN.CREATE)
        name = "foo"
        fd = await self.thr.task.open(await self.thr.ram.ptr(self.path/name), O.CREAT|O.EXCL)
        event = await watch.wait_until_event(IN.CREATE, name)
        self.assertEqual(event.name, name)
        self.assertEqual(event.mask, IN.CREATE)
