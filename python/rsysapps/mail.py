from __future__ import annotations
import email
import os
import abc
import trio
import socket
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.thread import Process
from rsyscall.handle import FileDescriptor, Path
from rsyscall.command import Command
from dataclasses import dataclass
from rsyscall.inotify_watch import Inotify
from rsyscall.mktemp import update_symlink

from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.sys.socket import AF, SOCK, Sockbuf
from rsyscall.fcntl import O
from rsyscall.unistd import SEEK
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.inotify import IN
from rsyscall.sys.memfd import MFD

class Dovecot:
    pass

class MailLocation:
    @abc.abstractmethod
    def spec(self) -> str: ...

@dataclass
class Maildir(MailLocation):
    path: Path
    @staticmethod
    async def make(thr: Process, path: Path) -> Maildir:
        self = Maildir(path)
        await thr.mkdir(self.path)
        await thr.mkdir(self.new())
        return self

    def spec(self) -> str:
        return "maildir:" + os.fsdecode(self.path)

    def new(self) -> Path:
        return self.path/'new'

async def start_dovecot(nursery, process: Process, path: Path,
                        lmtp_listener: FileDescriptor, mail: MailLocation) -> Dovecot:
    dovecot = await process.environ.which("dovecot")
    doveadm = await process.environ.which("doveadm")
    s6_ipcserverd = await process.environ.which("s6-ipcserverd")
    config = """
protocols =
log_path = /dev/stderr
mail_debug = yes
auth_debug = yes
service anvil {
  chroot =
}
service stats {
  chroot =
}
userdb {
  driver = static
  args = allow_all_users=yes
}
passdb {
  driver = passwd-file
  args = /dev/null
}
"""
    config += "base_dir = " + os.fsdecode(await process.mkdir(path/"base")) + "\n"
    config += "state_dir = " + os.fsdecode(await process.mkdir(path/"state")) + "\n"
    # unfortunately, dovecot requires names for these configuration parameters, and
    # doesn't accept ids. would be a nice patch to upstream...
    # TODO get these with id -n{u,g} I guess?
    username = "sbaugh"
    groupname = "sbaugh"
    config += f"default_login_user = {username}\n"
    config += f"default_internal_user = {username}\n"
    config += f"default_internal_group = {groupname}\n"
    # all mail we get from the socket goes to a single destination: this maildir
    config += f"mail_location = {mail.spec()}\n"

    config_path = await process.spit(path/"dovecot.conf", config)
    # start dovecot
    dovecot_process = await process.fork()
    dovecot_child = await dovecot_process.exec(dovecot.args('-F', '-c', config_path))
    nursery.start_soon(dovecot_child.check)

    # start lmtp server
    lmtp_process = await process.fork()
    lmtp_listener = lmtp_listener.move(lmtp_process.task)
    await lmtp_process.unshare_files(going_to_exec=True)
    await lmtp_process.stdin.replace_with(lmtp_listener)
    lmtp_child = await lmtp_process.exec(s6_ipcserverd.args(
        doveadm.executable_path, '-c', config_path, 'exec', 'lmtp'))
    nursery.start_soon(lmtp_child.check)
    return Dovecot()

@dataclass
class Smtpd:
    lmtp_socket_path: Path
    lmtp_listener: FileDescriptor
    config_file: Path

async def start_smtpd(nursery, process: Process, path: Path,
                      smtp_listener: FileDescriptor) -> Smtpd:
    smtpd = await process.environ.which("smtpd")
    smtpd_process = await process.fork()
    smtp_listener = smtp_listener.move(smtpd_process.task)
    await smtpd_process.unshare_files()

    config = ""
    config += 'listen on socket path "' + os.fsdecode(path/"smtpd.sock") + '"\n'
    config += "table aliases file:" + os.fsdecode(await process.spit(path/"aliases", "")) + "\n"
    config += 'queue path "' + os.fsdecode(await process.mkdir(path/"spool", mode=0o711)) + '"\n'
    config += 'path chroot "' + os.fsdecode(await process.mkdir(path/"empty")) + '"\n'
    config += "listen on localhost inherit " + str(await smtp_listener.as_argument()) + '\n'

    # bind a socket in the parent
    lmtp_socket = await process.task.socket(AF.UNIX, SOCK.STREAM)
    lmtp_socket_path = path/"lmtp.sock"
    await lmtp_socket.bind(await process.ram.ptr(SockaddrUn(os.fsencode(lmtp_socket_path))))
    await lmtp_socket.listen(10)
    config += 'action "local" lmtp "' + os.fsdecode(lmtp_socket_path) + '" user root\n'
    # all mail is delivered to this single socket
    # TODO actually dispatch correctly: we need one socket per username we accept
    config += 'match from any auth for local action "local"\n'

    config += 'action "relay" relay\n'
    config += 'match from local auth for any action "relay"\n'

    # smtpd has a lot of asserts that it is running as root, even
    # though we could arrange things so that it doesn't actually need
    # root. we'll put it in a user namespace so it gets its wish, and
    # run everything under "root", without privsep. "root" of course
    # is mapped to an unpriv user, so this is close to the same
    # security guarantee. we don't get separation between the main
    # user and the queue user, though... alas.
    await smtpd_process.unshare_user(in_namespace_uid=0, in_namespace_gid=0)
    config += "queue user root\n"
    config += "queue group root\n"
    config += "smtp user root\n"

    config_path = await process.spit(path/"smtpd.config", config)
    child = await smtpd_process.exec(smtpd.args("-v", "-d", "-f", config_path))
    nursery.start_soon(child.check)

    return Smtpd(
        lmtp_socket_path=lmtp_socket_path,
        lmtp_listener=lmtp_socket,
        config_file=config_path,
    )

import rsyscall.tasks.local as local
class TestMail(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.process = local.process
        self.tmpdir = await self.process.mkdtemp("test_mail")
        self.path = self.tmpdir.path
        await update_symlink(self.process, await self.process.ram.ptr(self.tmpdir.parent/"test_mail.current"), self.path)
        smtp_sock = await self.process.task.socket(AF.INET, SOCK.STREAM)
        await smtp_sock.bind(await self.process.ram.ptr(SockaddrIn(3000, "127.0.0.1")))
        await smtp_sock.listen(10)
        self.smtpd = await start_smtpd(self.nursery, self.process, await self.process.mkdir(self.path/"smtpd"), smtp_sock)
        self.maildir = await Maildir.make(self.process, self.path/"mail")
        self.dovecot = await start_dovecot(self.nursery, self.process, await self.process.mkdir(self.path/"dovecot"),
                                           self.smtpd.lmtp_listener, self.maildir)
        smtpctl = await self.process.environ.which("smtpctl")
        self.sendmail = Command(smtpctl.executable_path, [b'sendmail'], {'SMTPD_CONFIG_FILE': self.smtpd.config_file})
        self.inty = await Inotify.make(self.process)


    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def send_email(self, from_: str, to: str, subject: str, msg: str) -> None:
        process = await self.process.fork()
        await process.unshare_files()
        fd = await process.task.memfd_create(await process.ram.ptr(Path('message')))
        msg = f'From: {from_}\nSubject: {subject}\nTo: {to}\n\n' + msg
        await process.spit(fd, msg)
        await fd.lseek(0, SEEK.SET)
        await process.stdin.replace_with(fd)
        child = await process.exec(self.sendmail.args('-t'))
        await child.check()

    async def test_sendmail(self) -> None:
        watch = await self.inty.add(self.maildir.new(), IN.MOVED_TO)
        # TODO sigh, opensmtpd isn't validating the From field...
        from_ = 'from@localhost'
        to = 'sbaugh@localhost'
        subject = 'Subjective'
        msg = 'Hello me!\n'
        await self.send_email(from_, to, subject, msg)
        event = await watch.wait_until_event(IN.MOVED_TO)
        if event.name is None:
            raise Exception("event has no name??")
        mailfd = await self.process.task.open(await self.process.ram.ptr(self.maildir.new()/event.name), O.RDONLY)
        data = await self.process.read_to_eof(mailfd)
        message = email.message_from_bytes(data)
        self.assertEqual(from_,  message['From'])
        self.assertEqual(to,  message['To'])
        self.assertEqual(subject, message['Subject'])
        self.assertEqual(msg, message.get_payload())

    # So I need to set up proper DNS stuff.
    # Which... I can do by running my own DNS server :)
    # aha, okay, so I could have a DNS server which,
    # automatically forwards the requests to the NS server in the record
    async def test_mail_tester(self) -> None:
        from_ = 'sbaugh@catern.com'
        to = 'test-2ux4p@mail-tester.com'
        subject = 'Subjective'
        msg = 'Hello me!\n'
        await self.send_email(from_, to, subject, msg)
        await trio.sleep(9999)

if __name__ == "__main__":
    import unittest
    unittest.main()
