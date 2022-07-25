from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.unistd import O, SEEK
import logging

logger = logging.getLogger(__name__)

class TestSetuid(TrioTestCase):
    async def test_getdent_proc_pid_fd_after_setuid(self) -> None:
        "For some reason, we can still getdent on /proc/pid/fd after the target process setuids"
        other = await self.process.clone()
        other_file = await other.task.memfd_create("foo")
        logger.info("Disable cloexec so other_file actually gets inherited.")
        await other_file.disable_cloexec()

        logger.info("We can open /proc/pid/fd just fine right now...")
        proc_fds = await self.process.task.open(other.task.pid.as_proc_path()/"fd", O.RDONLY|O.DIRECTORY)
        logger.info("...and see other_file there.")
        for ent in await (await proc_fds.getdents()).read():
            if ent.name == str(int(other_file.near)):
                break
        else:
            raise AssertionError("expected to see", other_file, "in other's /proc/pid/fd")

        logger.info("Once we sudo, however...")
        sudo = await other.environ.which("sudo")
        async with await other.exec(sudo.args("sleep", "inf")):
            logger.info("...we can still see other_file in our old opened copy of /proc/pid/fd...")
            await proc_fds.lseek(0, SEEK.SET)
            for ent in await (await proc_fds.getdents()).read():
                if ent.name == str(int(other_file.near)):
                    break
            else:
                raise AssertionError("expected to see", other_file, "in other's /proc/pid/fd")

            logger.info("...but if we try to open /proc/pid/fd again, we get EPERM.")
            with self.assertRaises(PermissionError):
                await self.process.task.open(other.task.pid.as_proc_path()/"fd", O.RDONLY|O.DIRECTORY)
