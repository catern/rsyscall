import typing as t
import trio
import contextlib
import os
import socket
import unittest
from rsyscall.io import Command, SSHCommand, SSHDCommand
from rsyscall.io import Task, Path, build_local_stdtask, StandardTask
import rsyscall.io
import rsyscall.base as base
import logging

# local_stdtask = trio.run(build_local_stdtask, None)
# executable_dirs: t.List[base.Path] = []
# for prefix in local_stdtask.environment[b"PATH"].split(b":"):
#     executable_dirs.append(base.Path.from_bytes(local_stdtask.task.mount, local_stdtask.task.fs, prefix))

# ssh = local_stdtask.filesystem.utilities.ssh
# sshd = SSHDCommand.make(trio.run(which, local_stdtask.task, executable_dirs, b"sshd"))
# ssh_keygen = Command(trio.run(which, local_stdtask.task, executable_dirs, b"ssh-keygen"),
#                      ["ssh-keygen"], {})

@contextlib.asynccontextmanager
async def ssh_to_localhost(stdtask: StandardTask) -> t.AsyncGenerator[SSHCommand, None]:
    async with (await stdtask.mkdtemp()) as tmpdir:
        await stdtask.task.chdir(tmpdir)
        keygen_thread = await stdtask.fork()
        ssh_keygen = await rsyscall.io.which(stdtask, b"ssh-keygen")
        keygen_command = ssh_keygen.args(
            ['-b', '1024', '-q', '-N', '', '-C', '', '-f', 'key'])
        privkey = tmpdir/'key'
        pubkey = tmpdir/'key.pub'
        await (await keygen_command.exec(keygen_thread)).wait_for_exit()
        ssh = stdtask.filesystem.utilities.ssh
        sshd = SSHDCommand.make((await rsyscall.io.which(stdtask, b"sshd")).executable_path)
        sshd_command = sshd.args([
            '-i', '-f', '/dev/null',
        ]).sshd_options({
            'LogLevel': 'DEBUG',
            'HostKey': str(privkey.pure),
            'AuthorizedKeysFile': str(pubkey.pure),
            'StrictModes': 'no',
            'PrintLastLog': 'no',
            'PrintMotd': 'no',
        })
        yield ssh.args([
            '-F', '/dev/null',
        ]).ssh_options({
            'LogLevel': 'INFO',
            'IdentityFile': str(privkey.pure),
            'BatchMode': 'yes',
            'StrictHostKeyChecking': 'no',
            'UserKnownHostsFile': '/dev/null',
        }).proxy_command(sshd_command).args([
            "localhost",
        ])
            
# class TestSSH(unittest.TestCase):
#     async def runner(self, test: t.Callable[[], t.Awaitable[None]]) -> None:
#         async with (await local_stdtask.mkdtemp()) as tmpdir:
#             self.path = tmpdir.pure
#             await local_stdtask.task.chdir(tmpdir)
#             child_thread, [] = await local_stdtask.fork()
#             keygen_command = ssh_keygen.args(['-b', '1024', '-q', '-N', '', '-C', '', '-f', 'key'])
#             self.privkey = self.path/'key'
#             self.pubkey = self.path/'key.pub'
#             await (await keygen_command.exec(child_thread)).wait_for_exit()
#             sshd_command = sshd.args([
#                 '-i', '-f', '/dev/null',
#             ]).sshd_options({
#                 'LogLevel': 'DEBUG',
#                 'HostKey': str(self.privkey),
#                 'AuthorizedKeysFile': str(self.pubkey),
#                 'StrictModes': 'no',
#                 'PrintLastLog': 'no',
#                 'PrintMotd': 'no',
#             })
#             self.ssh_command = ssh.args([
#                 '-F', '/dev/null',
#             ]).ssh_options({
#                 'LogLevel': 'DEBUG',
#                 'IdentityFile': str(self.privkey),
#                 'BatchMode': 'yes',
#                 'StrictHostKeyChecking': 'no',
#                 'UserKnownHostsFile': '/dev/null',
#             }).proxy_command(sshd_command)
#             await test()

#     def test_true(self):
#         async def test() -> None:
#             sh = Command(local_stdtask.filesystem.utilities.sh, ['sh'], {})
#             child_thread = await local_stdtask.fork()
#             child_task = await sh.args(['-c', 'head key']).exec(child_thread)
#             await child_task.wait_for_exit()
#         trio.run(self.runner, test)
    
#     def test_helper(self):
#         async def test() -> None:
#             async with ssh_to_localhost(local_stdtask) as ssh_command:
#                 child_thread, [] = await local_stdtask.fork([])
#                 child_task = await ssh_command.args(['head key']).exec(child_thread)
#                 await child_task.wait_for_exit()
#         trio.run(test)

#     def test_ssh(self):
#         async def test() -> None:
#             pipe = await local_stdtask.task.pipe()
#             child_thread, [child_write] = await local_stdtask.fork([pipe.wfd.handle.far])
#             await child_thread.stdtask.stdout.replace_with(child_write)
#             await pipe.wfd.aclose()
#             child_task = await self.ssh_command.args(['localhost', 'cat ' + str(self.privkey)]).exec(child_thread)
#             pipe_data = await pipe.rfd.read()
#             privkey = await local_stdtask.task.open(self.privkey, os.O_RDONLY)
#             read_data = await local_stdtask.task.read(privkey)
#             self.assertEqual(pipe_data, read_data)
#         trio.run(self.runner, test)

#     def test_forward(self):
#         async def test() -> None:
#             listen_sock = await local_stdtask.task.socket_unix(socket.SOCK_STREAM)
#             listen_addr = self.path/"sock.listen"
#             await listen_sock.bind(listen_addr.unix_address())
#             await listen_sock.listen(10)
#             conn_addr = self.path/"sock.conn"

#             # set up some pipes for ssh
#             pipe_stdout = await local_stdtask.task.pipe()
#             pipe_stdin = await local_stdtask.task.pipe()
#             child_thread, [stdin, stdout] = await local_stdtask.fork([pipe_stdin.rfd.handle.far, pipe_stdout.wfd.handle.far])
#             await child_thread.stdtask.stdout.replace_with(stdout)
#             await child_thread.stdtask.stdin.replace_with(stdin)
#             await pipe_stdin.rfd.aclose()
#             await pipe_stdout.wfd.aclose()
#             to_stdin = pipe_stdin.wfd
#             from_stdout = pipe_stdout.rfd

#             # perform a forwarding
#             child_task = await self.ssh_command.local_forward(
#                 str(conn_addr), str(listen_addr),
#             ).args(['localhost', 'echo; cat']).exec(child_thread)
#             # ssh is started and the forwarding is done once it's written to stdout
#             await from_stdout.read()
#             await from_stdout.aclose()

#             dirfd = await local_stdtask.task.open(self.path, os.O_DIRECTORY)
#             print(await local_stdtask.task.getdents(dirfd))

#             conn_sock = await local_stdtask.task.socket_unix(socket.SOCK_STREAM)
#             # connect on a Unix socket doesn't block for accept
#             await conn_sock.connect(conn_addr.unix_address())
#             client_sock, client_addr = await listen_sock.accept(0)
#             data = b"hello"
#             await client_sock.write(data)
#             self.assertEqual(data, await conn_sock.read())
#             # shut down ssh by closing the other end of its stdin, causing cat to exit
#             await to_stdin.aclose()
#             # we must also close both ends of the connection!
#             await conn_sock.aclose()
#             await client_sock.aclose()
#             await child_task.wait_for_exit()
#         trio.run(self.runner, test)


