from __future__ import annotations
import rsyscall.handle as handle
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.memory as memory
from rsyscall.io import RsyscallThread, StandardTask, AsyncFileDescriptor, ChildProcess, SignalMask, UnixSocketFile, ProcessResources, FilesystemResources, ReadableFile, WritableFile, FileDescriptor, Command, AsyncReadBuffer, Path, RsyscallInterface, RsyscallConnection, SocketMemoryTransport, Task, ChildProcessMonitor, which, robust_unix_connect
from dataclasses import dataclass
import importlib.resources
import logging
import typing as t
import os
import contextlib
import abc
import random
import string

from rsyscall.fcntl import O
from rsyscall.sys.socket import SOCK, AF
ssh_bootstrap_script_contents = importlib.resources.read_text('rsyscall.tasks', 'ssh_bootstrap.sh')
logger = logging.getLogger(__name__)


T_ssh_command = t.TypeVar('T_ssh_command', bound="SSHCommand")
class SSHCommand(Command):
    def ssh_options(self, config: t.Mapping[str, t.Union[str, bytes, os.PathLike]]) -> SSHCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", os.fsdecode(key) + "=" + os.fsdecode(value)]
        return self.args(*option_list)

    def proxy_command(self, command: Command) -> SSHCommand:
        return self.ssh_options({'ProxyCommand': command.in_shell_form()})

    def local_forward(self, local_socket: handle.Path, remote_socket: str) -> SSHCommand:
        return self.args("-L", os.fsdecode(local_socket) + ":" + os.fsdecode(remote_socket))

    def as_host(self) -> ArbitrarySSHHost:
        return ArbitrarySSHHost(near.DirectoryFile(), self)

    @classmethod
    def make(cls: t.Type[T_ssh_command], executable_path: handle.Path) -> T_ssh_command:
        return cls(executable_path, [b"ssh"], {})

class SSHDCommand(Command):
    def sshd_options(self, config: t.Mapping[str, t.Union[str, bytes, os.PathLike]]) -> SSHDCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", os.fsdecode(key) + "=" + os.fsdecode(value)]
        return self.args(*option_list)

    @classmethod
    def make(cls, executable_path: handle.Path) -> SSHDCommand:
        return cls(executable_path, [b"sshd"], {})

# Need to identify the host, I guess
# I shouldn't abstract this too much - I should just use ssh.
@contextlib.asynccontextmanager
async def run_socket_binder(
        task: StandardTask,
        ssh_command: SSHCommand,
) -> t.AsyncGenerator[bytes, None]:
    stdout_pipe = await task.task.pipe()
    async_stdout = await AsyncFileDescriptor.make(task.epoller, stdout_pipe.rfd)
    thread = await task.fork()
    bootstrap_executable = await thread.stdtask.task.open(thread.stdtask.filesystem.rsyscall_bootstrap_path, O.RDONLY)
    stdout = thread.stdtask.task.base.make_fd_handle(stdout_pipe.wfd.handle)
    await stdout_pipe.wfd.handle.invalidate()
    await thread.stdtask.unshare_files()
    # TODO we are relying here on the fact that replace_with doesn't set cloexec on the new fd.
    # maybe we should explicitly list what we want to pass down...
    # or no, let's tag things as inheritable, maybe?
    await thread.stdtask.stdout.replace_with(stdout)
    await thread.stdtask.stdin.replace_with(bootstrap_executable)
    async with thread:
        child = await ssh_command.args(ssh_bootstrap_script_contents).exec(thread)
        # from... local?
        # I guess this throws into sharper relief the distinction between core and module.
        # The ssh bootstrapping stuff should come from a different class,
        # which hardcodes the path,
        # and which works only for local tasks.
        # So in the meantime we'll continue to get it from task.filesystem.

        # sigh, openssh doesn't close its local stdout when it sees HUP/EOF on
        # the remote stdout. so we can't use EOF to signal end of our lines, and
        # instead have to have a sentinel to tell us when to stop reading.
        lines_buf = AsyncReadBuffer(async_stdout)
        tmp_path_bytes = await lines_buf.read_line()
        if tmp_path_bytes is None:
            raise Exception("got EOF from ssh socket binder?")
        done = await lines_buf.read_line()
        if done != b"done":
            raise Exception("socket binder violated protocol, got instead of done:", done)
        await async_stdout.aclose()
        logger.info("socket bootstrap done, got tmp path %s", tmp_path_bytes)
        yield tmp_path_bytes
        (await child.wait_for_exit()).check()

async def ssh_forward(stdtask: StandardTask, ssh_command: SSHCommand,
                      local_path: handle.Path, remote_path: str) -> ChildProcess:
    stdout_pipe = await stdtask.task.pipe()
    async_stdout = await AsyncFileDescriptor.make(stdtask.epoller, stdout_pipe.rfd)
    thread = await stdtask.fork()
    stdout = thread.stdtask.task.base.make_fd_handle(stdout_pipe.wfd.handle)
    await stdout_pipe.wfd.invalidate()
    await thread.stdtask.unshare_files()
    await thread.stdtask.stdout.replace_with(stdout)
    child_task = await ssh_command.local_forward(
        local_path, remote_path,
    ).args("-n", "echo forwarded; sleep inf").exec(thread)
    lines_buf = AsyncReadBuffer(async_stdout)
    forwarded = await lines_buf.read_line()
    if forwarded != b"forwarded":
        raise Exception("ssh forwarding violated protocol, got instead of forwarded:", forwarded)
    await async_stdout.aclose()
    return child_task

async def ssh_bootstrap(
        parent_task: StandardTask,
        # the actual ssh command to run
        ssh_command: SSHCommand,
        # the root directory we'll have on the remote side
        ssh_root: near.DirectoryFile,
        # the local path we'll use for the socket
        local_socket_path: handle.Path,
        # the directory we're bootstrapping out of
        tmp_path_bytes: bytes,
) -> t.Tuple[ChildProcess, StandardTask]:
    # identify local path
    task = parent_task.task
    local_data_path = Path(task, local_socket_path)
    # start port forwarding; we'll just leak this process, no big deal
    forward_child = await ssh_forward(
        parent_task, ssh_command, local_socket_path, (tmp_path_bytes + b"/data").decode())
    # start bootstrap
    bootstrap_thread = await parent_task.fork()
    bootstrap_child_task = await ssh_command.args(
        "-n", f"cd {tmp_path_bytes.decode()}; ./bootstrap rsyscall"
    ).exec(bootstrap_thread)
    # TODO should unlink the bootstrap after I'm done execing.
    # it would be better if sh supported fexecve, then I could unlink it before I exec...
    # Connect to local socket 4 times
    async def make_async_connection() -> AsyncFileDescriptor[UnixSocketFile]:
        sock = await task.socket_unix(SOCK.STREAM)
        await robust_unix_connect(local_data_path, sock)
        return (await AsyncFileDescriptor.make(parent_task.epoller, sock))
    async_local_syscall_sock = await make_async_connection()
    async_local_data_sock = await make_async_connection()
    # Read description off of the data sock
    describe_buf = AsyncReadBuffer(async_local_data_sock)
    describe_struct = await describe_buf.read_cffi('struct rsyscall_bootstrap')
    new_pid = describe_struct.pid
    new_fd_table = far.FDTable(new_pid)
    def to_fd(num: int) -> far.FileDescriptor:
        return far.FileDescriptor(new_fd_table, near.FileDescriptor(num))
    listening_fd = to_fd(describe_struct.listening_sock)
    remote_syscall_fd = to_fd(describe_struct.syscall_sock)
    remote_data_fd = to_fd(describe_struct.data_sock)
    environ = await describe_buf.read_envp(describe_struct.envp_count)
    # Build the new task!
    new_address_space = far.AddressSpace(new_pid)
    # TODO the pid namespace will probably be common for all connections...
    new_pid_namespace = far.PidNamespace(new_pid)
    new_process = far.Process(new_pid_namespace, near.Process(new_pid))
    new_syscall = RsyscallInterface(RsyscallConnection(async_local_syscall_sock, async_local_syscall_sock),
                                    new_process.near, remote_syscall_fd.near)
    # the cwd is not the one from the ssh_host because we cd'd somewhere else as part of the bootstrap
    new_fs_information = far.FSInformation(new_pid, root=ssh_root, cwd=near.DirectoryFile())
    # TODO we should get this from the SSHHost, this is usually going
    # to be common for all connections and we should express that
    net = far.NetNamespace(new_pid)
    new_base_task = handle.Task(new_syscall, new_process, new_fd_table, new_address_space, new_fs_information,
                                new_pid_namespace, net)
    handle_remote_syscall_fd = new_base_task.make_fd_handle(remote_syscall_fd)
    new_syscall.store_remote_side_handles(handle_remote_syscall_fd, handle_remote_syscall_fd)
    handle_remote_data_fd = new_base_task.make_fd_handle(remote_data_fd)
    new_transport = SocketMemoryTransport(async_local_data_sock, handle_remote_data_fd)
    new_task = Task(new_base_task, new_transport,
                    memory.AllocatorClient.make_allocator(new_base_task),
                    # we assume ssh zeroes the sigmask before starting us
                    SignalMask(set()),
    )
    left_connecting_connection, right_connecting_connection = await new_task.socketpair(AF.UNIX, SOCK.STREAM, 0)
    connecting_connection = (left_connecting_connection.handle, right_connecting_connection.handle)
    epoller = await new_task.make_epoll_center()
    child_monitor = await ChildProcessMonitor.make(new_task, epoller)
    new_stdtask = StandardTask(
        access_task=parent_task.task,
        access_epoller=parent_task.epoller,
        access_connection=(local_data_path, new_task.make_fd(listening_fd.near, UnixSocketFile())),
        connecting_task=new_task, connecting_connection=connecting_connection,
        task=new_task,
        process_resources=ProcessResources.make_from_symbols(new_address_space, describe_struct.symbols),
        filesystem_resources=FilesystemResources.make_from_environ(new_base_task, environ),
        epoller=epoller,
        child_monitor=child_monitor,
        environment=environ,
        stdin=new_task._make_fd(0, ReadableFile(shared=True)),
        stdout=new_task._make_fd(1, WritableFile(shared=True)),
        stderr=new_task._make_fd(2, WritableFile(shared=True)),
    )
    return bootstrap_child_task, new_stdtask

async def spawn_ssh(
        task: StandardTask,
        ssh_command: SSHCommand,
        ssh_root: near.DirectoryFile,
        local_socket_path: handle.Path,
) -> t.Tuple[ChildProcess, StandardTask]:
    async with run_socket_binder(task, ssh_command) as tmp_path_bytes:
        return (await ssh_bootstrap(task, ssh_command, ssh_root, local_socket_path, tmp_path_bytes))

class SSHHost:
    @abc.abstractmethod
    async def ssh(self, task: StandardTask) -> t.Tuple[ChildProcess, StandardTask]: ...

@dataclass
class ArbitrarySSHHost(SSHHost):
    root: near.DirectoryFile
    command: SSHCommand
    async def ssh(self, task: StandardTask) -> t.Tuple[ChildProcess, StandardTask]:
        # we could get rid of the need to touch the local filesystem by directly
        # speaking the openssh multiplexer protocol. or directly speaking the ssh
        # protocol for that matter.
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = (self.guess_hostname()+random_suffix+".sock")
        local_socket_path: handle.Path = task.filesystem.tmpdir/name
        return (await spawn_ssh(task, self.command, self.root, local_socket_path))

    def guess_hostname(self) -> str:
        # we guess that the last argument of ssh command is the hostname. it
        # doesn't matter if it isn't, this is just for human-readability.
        return os.fsdecode(self.command.arguments[-1])


class LocalSSHHost(SSHHost):
    @staticmethod
    async def make(stdtask: StandardTask) -> LocalSSHHost:
        ssh_keygen = await which(stdtask, b"ssh-keygen")
        keygen_command = ssh_keygen.args('-b', '1024', '-q', '-N', '', '-C', '', '-f', 'key')
        keygen_thread = await stdtask.fork()
        async with (await stdtask.mkdtemp()) as tmpdir:
            await keygen_thread.stdtask.task.chdir(tmpdir)
            await (await keygen_command.exec(keygen_thread)).wait_for_exit()
            privkey_file = await (tmpdir/'key').open(O.RDONLY)
            pubkey_file = await (tmpdir/'key.pub').open(O.RDONLY)
        privkey = privkey_file.handle.as_proc_path()
        pubkey = pubkey_file.handle.as_proc_path()
        ssh = SSHCommand.make((await which(stdtask, b"ssh")).executable_path)
        sshd = SSHDCommand.make((await which(stdtask, b"sshd")).executable_path)
        sshd_command = sshd.args(
            '-i', '-e', '-f', '/dev/null',
        ).sshd_options({
            'LogLevel': 'INFO',
            'HostKey': privkey,
            'AuthorizedKeysFile': pubkey,
            'StrictModes': 'no',
            'PrintLastLog': 'no',
            'PrintMotd': 'no',
        })
        ssh_command = ssh.args(
            '-F', '/dev/null',
        ).ssh_options({
            'LogLevel': 'INFO',
            'IdentityFile': privkey,
            'BatchMode': 'yes',
            'StrictHostKeyChecking': 'no',
            'UserKnownHostsFile': '/dev/null',
        }).proxy_command(sshd_command).args(
            "localhost",
        )
        return LocalSSHHost(ssh_command, privkey_file, pubkey_file)

    async def ssh(self, task: StandardTask) -> t.Tuple[ChildProcess, StandardTask]:
        # we could get rid of the need to touch the local filesystem by directly
        # speaking the openssh multiplexer protocol. or directly speaking the ssh
        # protocol for that matter.
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = "local_ssh."+random_suffix+".sock"
        local_socket_path: handle.Path = task.filesystem.tmpdir/name
        async with run_socket_binder(task, self.command) as tmp_path_bytes:
            return (await ssh_bootstrap(task, self.command, task.task.base.fs.root, local_socket_path, tmp_path_bytes))

    def __init__(self, command: SSHCommand,
                 privkey: FileDescriptor[ReadableFile],
                 pubkey: FileDescriptor[ReadableFile],
    ) -> None:
        self.command = command
        self.privkey = privkey
        self.pubkey = pubkey


@contextlib.asynccontextmanager
async def ssh_to_localhost(stdtask: StandardTask) -> t.AsyncGenerator[SSHHost, None]:
    yield (await LocalSSHHost.make(stdtask))
