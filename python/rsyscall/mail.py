from __future__ import annotations
import email
import os
import abc
import trio
import socket
import rsyscall.io as rsc
import rsyscall.sys.inotify as inotify
import rsyscall.handle as handle
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.io import StandardTask, RsyscallThread, Path, Command
from rsyscall.io import FileDescriptor, ReadableWritableFile, ChildProcess
from dataclasses import dataclass

from rsyscall.netinet.in_ import SockaddrIn

class Dovecot:
    pass

class MailLocation:
    @abc.abstractmethod
    def spec(self) -> str: ...

@dataclass
class Maildir(MailLocation):
    path: Path
    @staticmethod
    async def make(path: Path) -> Maildir:
        self = Maildir(path)
        await self.path.mkdir()
        await self.new().mkdir()
        return self

    def spec(self) -> str:
        return "maildir:" + os.fsdecode(self.path)

    def new(self) -> Path:
        return self.path/'new'

async def start_dovecot(nursery, stdtask: StandardTask, path: Path,
                        lmtp_listener: handle.FileDescriptor, mail: MailLocation) -> Dovecot:
    dovecot = await rsc.which(stdtask, "dovecot")
    doveadm = await rsc.which(stdtask, "doveadm")
    s6_ipcserverd = await rsc.which(stdtask, "s6-ipcserverd")
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
    config += "base_dir = " + os.fsdecode(await (path/"base").mkdir()) + "\n"
    config += "state_dir = " + os.fsdecode(await (path/"state").mkdir()) + "\n"
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

    config_path = await rsc.spit(path/"dovecot.conf", config)
    # start dovecot
    dovecot_thread = await stdtask.fork()
    dovecot_child = await dovecot_thread.exec(dovecot.args('-F', '-c', config_path))
    nursery.start_soon(dovecot_child.check)

    # start lmtp server
    lmtp_thread = await stdtask.fork()
    lmtp_listener = lmtp_listener.move(lmtp_thread.stdtask.task.base)
    await lmtp_thread.stdtask.unshare_files(going_to_exec=True)
    await lmtp_thread.stdtask.stdin.replace_with(lmtp_listener)
    lmtp_child = await lmtp_thread.exec(s6_ipcserverd.args(
        doveadm.executable_path, '-c', config_path, 'exec', 'lmtp'))
    nursery.start_soon(lmtp_child.check)
    return Dovecot()

@dataclass
class Smtpd:
    lmtp_socket_path: Path
    lmtp_listener: handle.FileDescriptor
    config_file: Path

async def start_smtpd(nursery, stdtask: StandardTask, path: Path,
                      smtp_listener: handle.FileDescriptor) -> Smtpd:
    smtpd = await rsc.which(stdtask, "smtpd")
    thread = await stdtask.fork()
    smtp_listener = smtp_listener.move(thread.stdtask.task.base)
    await thread.stdtask.unshare_files(going_to_exec=True)

    config = ""
    config += 'listen on socket path "' + os.fsdecode(path/"smtpd.sock") + '"\n'
    config += "table aliases file:" + os.fsdecode(await rsc.spit(path/"aliases", "")) + "\n"
    config += 'queue path "' + os.fsdecode(await (path/"spool").mkdir(mode=0o711)) + '"\n'
    config += 'path chroot "' + os.fsdecode(await (path/"empty").mkdir()) + '"\n'
    config += "listen on localhost inherit " + str(await smtp_listener.as_argument()) + '\n'

    # bind a socket in the parent
    lmtp_socket = await stdtask.task.socket_unix(socket.SOCK_STREAM, cloexec=False)
    lmtp_socket_path = path/"lmtp.sock"
    await lmtp_socket.bind(lmtp_socket_path.unix_address())
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
    await thread.stdtask.unshare_user(in_namespace_uid=0, in_namespace_gid=0)
    config += "queue user root\n"
    config += "queue group root\n"
    config += "smtp user root\n"

    config_path = await rsc.spit(path/"smtpd.config", config)
    child = await thread.exec(smtpd.args("-v", "-d", "-f", config_path))
    nursery.start_soon(child.check)

    return Smtpd(
        lmtp_socket_path=lmtp_socket_path,
        lmtp_listener=lmtp_socket.handle,
        config_file=config_path,
    )

class TestMail(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = rsc.local_stdtask
        self.tmpdir = await self.stdtask.mkdtemp("test_mail")
        await rsc.update_symlink(self.tmpdir.parent, "test_mail.current", os.fsdecode(self.tmpdir.name))
        self.path = self.tmpdir.path
        smtp_sock = await self.stdtask.task.socket_inet(socket.SOCK_STREAM)
        await smtp_sock.bind(SockaddrIn(3000, 0x7F_00_00_01))
        await smtp_sock.listen(10)
        self.smtpd = await start_smtpd(self.nursery, self.stdtask, await (self.path/"smtpd").mkdir(), smtp_sock.handle)
        self.maildir = await Maildir.make(self.path/"mail")
        self.dovecot = await start_dovecot(self.nursery, self.stdtask, await (self.path/"dovecot").mkdir(),
                                           self.smtpd.lmtp_listener, self.maildir)
        smtpctl = await rsc.which(self.stdtask, "smtpctl")
        self.sendmail = Command(smtpctl.executable_path, [b'sendmail'], {'SMTPD_CONFIG_FILE': self.smtpd.config_file})
        self.inty = await inotify.Inotify.make(self.stdtask)


    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def send_email(self, from_: str, to: str, subject: str, msg: str) -> None:
        thread = await self.stdtask.fork()
        await thread.stdtask.unshare_files(going_to_exec=True)
        fd = await thread.stdtask.task.memfd_create('message')
        msg = f'From: {from_}\nSubject: {subject}\nTo: {to}\n\n' + msg
        await fd.write_all(msg.encode())
        await fd.lseek(0, os.SEEK_SET)
        await thread.stdtask.stdin.replace_with(fd.handle)
        child = await thread.exec(self.sendmail.args('-t'))
        await child.check()

    async def test_sendmail(self) -> None:
        watch = await self.inty.add(self.maildir.new().handle, inotify.Mask.MOVED_TO)
        # TODO sigh, opensmtpd isn't validating the From field...
        from_ = 'from@localhost'
        to = 'sbaugh@localhost'
        subject = 'Subjective'
        msg = 'Hello me!\n'
        await self.send_email(from_, to, subject, msg)
        event = await watch.wait_until_event(inotify.Mask.MOVED_TO)
        mailfd = await (self.maildir.new()/event.name).open(os.O_RDONLY)
        data = await rsc.read_all(mailfd)
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
