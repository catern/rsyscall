from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.sys.inotify import *
from rsyscall.inotify_watch import Inotify
from rsyscall.fcntl import O
from rsyscall.stdlib import mkdtemp

class TestInotify(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(self.process)
        self.ify = await Inotify.make(self.process)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_create(self) -> None:
        watch = await self.ify.add(self.tmpdir, IN.CREATE)
        name = "foo"
        fd = await self.process.task.open(await self.process.ram.ptr(self.tmpdir/name), O.CREAT|O.EXCL)
        event = await watch.wait_until_event(IN.CREATE, name)
        self.assertEqual(event.name, name)
        self.assertEqual(event.mask, IN.CREATE)
