from __future__ import annotations
import rsyscall.handle as handle
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.memory.allocator as memory
from rsyscall.io import RsyscallThread, StandardTask, AsyncFileDescriptor, ChildProcess, UnixSocketFile, ProcessResources, ReadableFile, WritableFile, FileDescriptor, Command, AsyncReadBuffer, Path, RsyscallInterface, RsyscallConnection, SocketMemoryTransport, Task, ChildProcessMonitor, which, robust_unix_connect
from dataclasses import dataclass
import importlib.resources
import logging
import typing as t
import os
import contextlib
import abc
import random
import string

import rsyscall.nix as nix
from rsyscall.fcntl import O
from rsyscall.sys.socket import SOCK, AF

__all__ = [
    "SSHCommand",
    "SSHDCommand",
    "SSHExecutables",
    "SSHDExecutables",
    "make_local_ssh_from_executables",
    "make_ssh_host",
    "make_local_ssh",
]

ssh_bootstrap_script_contents = importlib.resources.read_text('rsyscall.tasks', 'ssh_bootstrap.sh')
logger = logging.getLogger(__name__)

openssh = nix.import_nix_dep("openssh")

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

@dataclass
class SSHExecutables:
    base_ssh: SSHCommand
    bootstrap_executable: handle.FileDescriptor

    @classmethod
    async def from_store(cls, store: nix.Store) -> SSHExecutables:
        ssh_path = await store.realise(openssh)
        rsyscall_path = await store.realise(nix.rsyscall)
        base_ssh = SSHCommand.make(ssh_path.handle/"bin"/"ssh")
        bootstrap_executable = (await (rsyscall_path/"libexec"/"rsyscall"/"rsyscall-bootstrap").open(O.RDONLY)).handle
        return SSHExecutables(base_ssh, bootstrap_executable)

    def host(self, to_host: t.Callable[[SSHCommand], SSHCommand]) -> SSHHost:
        """Create an object for sshing to a host.

        Important design decision here: the user doesn't pass in a
        hostname, username, various options, etc etc.

        Instead, they just give us a partial ssh command that we'll
        then use to do the sshing by appending our own shell command
        arguments.

        This allows using fancy options, connection sharing, all kinds
        of stuff, without us having to explicitly support it.

        The only constraint is that the user (obviously) shouldn't
        include an actual shell command in their ssh command.

        ---

        There's a further design decision here: We take a function
        instead of a completed SSHCommand. This is just so that we can
        pass in the basic SSHCommand to use, and then the user can
        extend it - it gives both us and the user the ability to add
        arbitrary exciting arguments.

        """
        return SSHHost(self, to_host)

@dataclass
class SSHHost:
    executables: SSHExecutables
    to_host: t.Any[t.Callable[[SSHCommand], SSHCommand]]
    async def ssh(self, task: StandardTask) -> t.Tuple[ChildProcess, StandardTask]:
        # we could get rid of the need to touch the local filesystem by directly
        # speaking the openssh multiplexer protocol. or directly speaking the ssh
        # protocol for that matter.
        ssh_to_host = self.to_host(self.executables.base_ssh)
        # we guess that the last argument of ssh command is the hostname. it
        # doesn't matter if it isn't, this is just used for a temp filename,
        # just to be more human-readable
        hostname = os.fsdecode(ssh_to_host.arguments[-1])
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = (hostname+random_suffix+".sock")
        local_socket_path: handle.Path = task.tmpdir/name
        # TODO let's check up front that the bootstrap_executable is in this task's fd space?
        async with run_socket_binder(task, ssh_to_host, self.executables.bootstrap_executable) as tmp_path_bytes:
            return (await ssh_bootstrap(task, ssh_to_host, local_socket_path, tmp_path_bytes))

@contextlib.asynccontextmanager
async def run_socket_binder(
        task: StandardTask,
        ssh_command: SSHCommand,
        bootstrap_executable: handle.FileDescriptor,
) -> t.AsyncGenerator[bytes, None]:
    stdout_pipe = await task.task.pipe()
    async_stdout = await task.make_afd(stdout_pipe.rfd.handle)
    thread = await task.fork()
    stdout = thread.stdtask.task.base.make_fd_handle(stdout_pipe.wfd.handle)
    await stdout_pipe.wfd.handle.invalidate()
    with bootstrap_executable.borrow(thread.stdtask.task.base) as bootstrap_executable:
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
    async_stdout = await stdtask.make_afd(stdout_pipe.rfd.handle)
    thread = await stdtask.fork()
    stdout = thread.stdtask.task.base.make_fd_handle(stdout_pipe.wfd.handle)
    await stdout_pipe.wfd.invalidate()
    await thread.stdtask.unshare_files()
    await thread.stdtask.stdout.replace_with(stdout)
    child_task = await ssh_command.local_forward(
        local_path, remote_path,
    # TODO I optimistically assume that I'll have established a
    # connection through the tunnel before 1 second has passed;
    # that connection will then keep the tunnel open.
    ).args("-n", "echo forwarded; exec sleep 1").exec(thread)
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
        # the local path we'll use for the socket
        local_socket_path: handle.Path,
        # the directory we're bootstrapping out of
        tmp_path_bytes: bytes,
) -> t.Tuple[ChildProcess, StandardTask]:
    # identify local path
    task = parent_task.task
    local_data_path = Path(task, local_socket_path)
    # start port forwarding; we'll just leak this process, no big deal
    # TODO we shouldn't leak processes; we should be GCing processes at some point
    forward_child = await ssh_forward(
        parent_task, ssh_command, local_socket_path, (tmp_path_bytes + b"/data").decode())
    # start bootstrap
    bootstrap_thread = await parent_task.fork()
    bootstrap_child_task = await ssh_command.args(
        "-n", f"cd {tmp_path_bytes.decode()}; exec ./bootstrap rsyscall"
    ).exec(bootstrap_thread)
    # TODO should unlink the bootstrap after I'm done execing.
    # it would be better if sh supported fexecve, then I could unlink it before I exec...
    # Connect to local socket 4 times
    async def make_async_connection() -> AsyncFileDescriptor:
        sock = await parent_task.make_afd(await task.base.socket(AF.UNIX, SOCK.STREAM))
        async with local_data_path.as_sockaddr_un() as addr:
            await sock.connect(addr)
        return sock
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
    new_fs_information = far.FSInformation(new_pid)
    # TODO we should get this from the SSHHost, this is usually going
    # to be common for all connections and we should express that
    net = far.NetNamespace(new_pid)
    new_base_task = handle.Task(new_syscall, new_process.near, None, new_fd_table, new_address_space, new_fs_information,
                                new_pid_namespace, net)
    handle_remote_syscall_fd = new_base_task.make_fd_handle(remote_syscall_fd)
    new_syscall.store_remote_side_handles(handle_remote_syscall_fd, handle_remote_syscall_fd)
    handle_remote_data_fd = new_base_task.make_fd_handle(remote_data_fd)
    new_allocator = memory.AllocatorClient.make_allocator(new_base_task)
    new_transport = SocketMemoryTransport(async_local_data_sock,
                                          handle_remote_data_fd, new_allocator)
    # we don't inherit SignalMask; we assume ssh zeroes the sigmask before starting us
    new_task = Task(new_base_task, new_transport, new_allocator)
    left_connecting_connection, right_connecting_connection = await new_task.socketpair(AF.UNIX, SOCK.STREAM, 0)
    connecting_connection = (left_connecting_connection.handle, right_connecting_connection.handle)
    epoller = await new_task.make_epoll_center()
    child_monitor = await ChildProcessMonitor.make(new_task, new_task.base, epoller)
    new_stdtask = StandardTask(
        access_task=parent_task.task,
        access_epoller=parent_task.epoller,
        access_connection=(local_data_path, new_task.make_fd(listening_fd.near, UnixSocketFile())),
        connecting_task=new_task, connecting_connection=connecting_connection,
        task=new_task,
        process_resources=ProcessResources.make_from_symbols(new_base_task, describe_struct.symbols),
        epoller=epoller,
        child_monitor=child_monitor,
        environment=environ,
        stdin=new_task._make_fd(0, ReadableFile(shared=True)),
        stdout=new_task._make_fd(1, WritableFile(shared=True)),
        stderr=new_task._make_fd(2, WritableFile(shared=True)),
    )
    return bootstrap_child_task, new_stdtask

@dataclass
class SSHDExecutables:
    ssh_keygen: Command
    sshd: SSHDCommand

    @classmethod
    async def from_store(cls, store: nix.Store) -> SSHDExecutables:
        ssh_path = await store.realise(openssh)
        ssh_keygen = Command(ssh_path.handle/"bin"/"ssh-keygen", ["ssh-keygen"], {})
        sshd = SSHDCommand.make(ssh_path.handle/"bin"/"sshd")
        return SSHDExecutables(ssh_keygen, sshd)

async def make_local_ssh_from_executables(stdtask: StandardTask,
                                          executables: SSHExecutables, sshd_executables: SSHDExecutables) -> SSHHost:
    ssh_keygen = sshd_executables.ssh_keygen
    sshd = sshd_executables.sshd

    keygen_command = ssh_keygen.args('-b', '1024', '-q', '-N', '', '-C', '', '-f', 'key')
    keygen_thread = await stdtask.fork()
    # ugh, we have to make a directory because ssh-keygen really wants to output to a directory
    async with (await stdtask.mkdtemp()) as tmpdir:
        await keygen_thread.stdtask.task.base.chdir(await tmpdir.to_pointer())
        await (await keygen_command.exec(keygen_thread)).wait_for_exit()
        privkey_file = await (tmpdir/'key').open(O.RDONLY)
        pubkey_file = await (tmpdir/'key.pub').open(O.RDONLY)
    def to_host(ssh: SSHCommand, privkey_file=privkey_file, pubkey_file=pubkey_file) -> SSHCommand:
        privkey = privkey_file.handle.as_proc_path()
        pubkey = pubkey_file.handle.as_proc_path()
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
        return ssh_command
    return executables.host(to_host)

# Helpers
async def make_ssh_host(store: nix.Store, to_host: t.Callable[[SSHCommand], SSHCommand]) -> SSHHost:
    ssh = await SSHExecutables.from_store(store)
    return ssh.host(to_host)

async def make_local_ssh(stdtask: StandardTask, store: nix.Store) -> SSHHost:
    ssh = await SSHExecutables.from_store(store)
    sshd = await SSHDExecutables.from_store(store)
    return (await make_local_ssh_from_executables(stdtask, ssh, sshd))


