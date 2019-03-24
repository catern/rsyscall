import os
import trio
import rsyscall.io as rsc
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.io import StandardTask, RsyscallThread, Path, Command
from rsyscall.io import FileDescriptor, ReadableWritableFile, ChildProcess
from dataclasses import dataclass

class Dovecot:
    pass

class MailLocation:
    @abc.abstractmethod
    def spec(self) -> str: ...

@dataclass
class Maildir(MailLocation):
    path: Path
    def spec(self) -> str:
        return "maildir:" + os.fsdecode(path)

async def start_dovecot(nursery, stdtask: StandardTask, path: Path,
                        lmtp_listener: handle.FileDescriptor, mail: MailLocation) -> Dovecot:
    # start up dovecot, delivering to our home directory, and listening on lmtp under this path
    # maybe should not deliver to our homedir, but rather a maildir passed in...
    # yeah yeah, mail location...
    # oh, uh.
    # dovecot should I guess get a socket passed down. hmm. I want to pass in a socket, for sure...
    # MEH let's do it with s6. anyway if we do it that way, then smtpd can gate the rate of message sending
    # yeah okay! because it makes more sense anyway to do that stuff in the MTA
    pass

class Smtpd:
    pass

async def start_smtpd(nursery, stdtask: StandardTask, path: Path,
                      lmtp: Path) -> Smtpd:
    # start up smtpd, delivering to this lmtp path
    # hmm wait though, we want a different lmtp path for each
    # okay makes sense! we'll tell smtpd, here are the delivery things,
    # and it gives us back sockets. what's the exact api though?
    pass

class TestMail(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = rsc.local_stdtask
        self.tmpdir = await self.stdtask.mkdtemp("test_mail")
        await rsc.update_symlink(self.tmpdir.parent, "test_mail.current", os.fsdecode(self.tmpdir.name))
        self.path = self.tmpdir.path

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

if __name__ == "__main__":
    import unittest
    unittest.main()
