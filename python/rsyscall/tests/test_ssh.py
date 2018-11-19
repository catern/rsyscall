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
            child_thread, [] = await local_stdtask.fork()
            keygen_command = ssh_keygen.args(['-b', '1024', '-q', '-N', '', '-C', '', '-f', 'key'])
            self.privkey = self.path/'key'
            self.pubkey = self.path/'key.pub'
            await (await keygen_command.exec(child_thread)).wait_for_exit()
            await test()

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
            pipe = await local_stdtask.task.pipe()
            child_thread, [child_write] = await local_stdtask.fork([pipe.wfd.active.far])
            await child_thread.stdtask.stdout.replace_with(child_write)
            await pipe.wfd.aclose()
            child_task = await ssh_command.args(['head ' + str(self.privkey)]).exec(child_thread)
            data = await pipe.rfd.read()
            # TODO open file and compare data
            privkey = await local_stdtask.task.open(self.privkey)
            # paths don't own so I don't like this path object abstraction anymore
            # but I do need it for file descriptors...
            privkey
            print(data)
        trio.run(self.runner, test)


