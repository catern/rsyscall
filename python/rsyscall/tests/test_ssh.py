import typing as t
import trio
import unittest
from rsyscall.ssh import Command, SSHCommand, SSHDCommand
from rsyscall.io import local_stdtask, Task, Path
import rsyscall.base as base
import logging

executable_dirs: t.List[base.Path] = []
for prefix in local_stdtask.environment[b"PATH"].split(b":"):
    executable_dirs.append(base.Path.from_bytes(local_stdtask.task.mount, local_stdtask.task.fs, prefix))
async def which(task: Task, paths: t.List[base.Path], name: bytes) -> base.Path:
    "Find an executable by this name in this list of paths"
    if b"/" in name:
        raise Exception("name should be a single path element without any / present")
    for path in paths:
        filename = Path(task, path)/name
        if (await filename.access(read=True, execute=True)):
            return filename.pure
    raise Exception("executable not found", name)

ssh = SSHCommand.make(local_stdtask.filesystem.utilities.ssh)
sshd = SSHDCommand.make(trio.run(which, local_stdtask.task, executable_dirs, b"sshd"))
ssh_keygen = Command.make(trio.run(which, local_stdtask.task, executable_dirs, b"ssh-keygen"),
                          b"ssh-keygen")

class TestSSH(unittest.TestCase):
    async def runner(self, test: t.Callable[[], t.Awaitable[None]]) -> None:
        async with (await local_stdtask.mkdtemp()) as tmpdir:
            self.path = tmpdir.pure
            await local_stdtask.task.chdir(tmpdir)
            child_thread = await local_stdtask.fork()
            keygen_command = ssh_keygen.args(['-b', '1024', '-q', '-N', '', '-C', '', '-f', 'key'])
            self.privkey = self.path/'key'
            self.pubkey = self.path/'key.pub'
            await (await keygen_command.exec(child_thread)).wait_for_exit()
            await test()
        # mktemp
        # ssh-keygen
        # ssh
        # gotta put those all into the .so I guess
        # hmm well we don't actually need ssh-keygen at runtime, nor sshd.
        # just for testing
        # does that mean we should look them up with which?
        # instead of recording them in the .so?
        # how do we make that nice and uniform tho...
        # hmm... so some dependencies I don't want to have at test time...
        # Does that kind of mean, my tests should depend on my real library?
        # They should be a separate derivation?
        # But, I want my tests to pass...
        # My tests are a certificate of correctness,
        # but I don't want that certificate to depend on various things.
        # Hmm.
        # I guess if I depend on the library.... well, that still puts things on the path.
        # If I depend on the library, and hardcode my deps...
        # I'll look them up with which, it's no big deal.
        # I'll use an rsyscall which, of course.
        # Nah, depending on everything that my tests require is good.
        # Wait no it's not good, I could require systemd and stuff at somep oint.
        # Well, I can use shutil which...
        # That will be faster than rsyscall which, I guess.
        # Well, I need ssh-keygen...
        # sshd...
        # um...
        # hey I might also want to regression test against old sshds and stuff.
        # so, yeah.
        # we'll use shutil which I guess
        # no built in which
    
    def test_true(self):
        async def test() -> None:
            sh = Command.make(local_stdtask.filesystem.utilities.sh, 'sh')
            child_thread = await local_stdtask.fork()
            child_task = await sh.args(['-c', 'head key']).exec(child_thread)
            await child_task.wait_for_exit()
        trio.run(self.runner, test)
    
    def test_ssh(self):
        async def test() -> None:
            sshd_command = sshd.args([
                '-i', '-f', '/dev/null',
            ]).sshd_options({
                'LogLevel': 'QUIET',
                'HostKey': str(self.privkey),
                'AuthorizedKeysFile': str(self.pubkey),
                'StrictModes': 'no',
                'PrintLastLog': 'no',
                'PrintMotd': 'no',
            })
            ssh_command = ssh.args([
                '-F', '/dev/null',
            ]).ssh_options({
                'LogLevel': 'QUIET',
                'IdentityFile': str(self.privkey),
                'BatchMode': 'yes',
                'StrictHostKeyChecking': 'no',
                'UserKnownHostsFile': '/dev/null',
            }).proxy_command(sshd_command).args([
                'localhost',
            ])
            child_thread = await local_stdtask.fork()
            # redirect stdout so we can get this output of head...
            child_task = await ssh_command.args(['head ' + str(self.privkey)]).exec(child_thread)
            await child_task.wait_for_exit()
        trio.run(self.runner, test)


