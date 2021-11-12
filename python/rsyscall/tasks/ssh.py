"""A thread on a remote host, bootstrapped over ssh

Note that all thread types can be launched through any other thread type,
including through an ssh thread.
"""
from __future__ import annotations
from dataclasses import dataclass
from rsyscall.command import Command
from rsyscall.environ import Environment
from rsyscall.epoller import Epoller, AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.handle import WrittenPointer, FileDescriptor, Task
from rsyscall.thread import Thread
from rsyscall.loader import NativeLoader
from rsyscall.memory.ram import RAM
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.network.connection import ListeningConnection
from rsyscall.path import Path
from rsyscall.sched import CLONE
from rsyscall.tasks.connection import SyscallConnection
import abc
import contextlib
import importlib.resources
import logging
import os
import random
import rsyscall.far as far
import rsyscall.handle as handle
import rsyscall.memory.allocator as memory
import rsyscall.near.types as near
import rsyscall.nix as nix
import string
import typing as t

from rsyscall.fcntl import O, F
from rsyscall.stdlib import mkdtemp
from rsyscall.sys.socket import SOCK, AF
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.wait import W
from rsyscall.unistd import Pipe

__all__ = [
    "SSHCommand",
    "SSHDCommand",
    "SSHExecutables",
    "SSHDExecutables",
    "SSHHost",
    "make_local_ssh_from_executables",
    "make_ssh_host",
    "make_local_ssh",
]

ssh_bootstrap_script_contents = importlib.resources.read_text('rsyscall.tasks', 'ssh_bootstrap.sh')
logger = logging.getLogger(__name__)

T_ssh_command = t.TypeVar('T_ssh_command', bound="SSHCommand")
class SSHCommand(Command):
    "The 'ssh' executable provided by OpenSSH, plus some arguments and special methods"
    def ssh_options(self, config: t.Mapping[str, t.Union[str, bytes, os.PathLike]]) -> SSHCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", os.fsdecode(key) + "=" + os.fsdecode(value)]
        return self.args(*option_list)

    def proxy_command(self, command: Command) -> SSHCommand:
        return self.ssh_options({'ProxyCommand': command.in_shell_form()})

    def local_forward(self, local_socket: str, remote_socket: str) -> SSHCommand:
        return self.args("-L", os.fsdecode(local_socket) + ":" + os.fsdecode(remote_socket))

    @classmethod
    def make(cls: t.Type[T_ssh_command], executable_path: Path) -> T_ssh_command:
        return cls(executable_path, ["ssh"], {})

class SSHDCommand(Command):
    "The 'sshd' executable provided by OpenSSH, plus some arguments and special methods"
    def sshd_options(self, config: t.Mapping[str, t.Union[str, bytes, os.PathLike]]) -> SSHDCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", os.fsdecode(key) + "=" + os.fsdecode(value)]
        return self.args(*option_list)

    @classmethod
    def make(cls, executable_path: Path) -> SSHDCommand:
        return cls(executable_path, ["sshd"], {})

@dataclass
class SSHExecutables:
    """A standalone representation of the executables needed to create an SSH thread

    This is not really a user-facing class, it exists just to promote modularity. With
    this class, our functions need only take an object of this type, rather than look up
    the location of the executables themselves; therefore we can add new ways to look up
    executables and create this class without having to teach our functions about them.

    """
    base_ssh: SSHCommand
    bootstrap_path: Path

    @classmethod
    async def with_nix(cls, thread: Thread) -> SSHExecutables:
        import rsyscall._nixdeps.openssh
        import rsyscall._nixdeps.librsyscall
        ssh_path = await nix.deploy(thread, rsyscall._nixdeps.openssh.closure)
        rsyscall_path = await nix.deploy(thread, rsyscall._nixdeps.librsyscall.closure)
        base_ssh = SSHCommand.make(ssh_path/"bin"/"ssh")
        bootstrap_path = rsyscall_path/"libexec"/"rsyscall"/"rsyscall-bootstrap"
        return SSHExecutables(base_ssh, bootstrap_path)

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

class SSHHost:
    """A host we can ssh to, based on some ssh command

    We don't actually know what host we're going to ssh to - that's entirely determined by
    the user-provided to_host function. Presumably that function is deterministic, so
    we'll ssh to the same host each time...

    """
    def __init__(self,
                 executables: SSHExecutables,
                 to_host: t.Callable[[SSHCommand], SSHCommand]) -> None:
        self.executables = executables
        self.to_host = to_host

    async def ssh(self, thread: Thread) -> t.Tuple[AsyncChildProcess, Thread]:
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
        local_socket_path = thread.environ.tmpdir/name
        fd = await thread.task.open(await thread.ram.ptr(self.executables.bootstrap_path), O.RDONLY)
        async with make_bootstrap_dir(thread, ssh_to_host, fd) as tmp_path_bytes:
            return await ssh_bootstrap(thread, ssh_to_host, local_socket_path, tmp_path_bytes)

@contextlib.asynccontextmanager
async def make_bootstrap_dir(
        parent: Thread,
        ssh_command: SSHCommand,
        bootstrap_executable: FileDescriptor,
) -> t.AsyncGenerator[bytes, None]:
    """Over ssh, make a temporary directory containing the bootstrap executable, and start the socket bootstrap server

    The socket bootstrap server listens on two sockets in this temporary directory. One of
    them, we'll ssh forward back to the local host. The other, the main bootstrap process
    will connect to, to grab the listening socket fd for the former, so we can accept
    connections.

    We'll also use the bootstrap executable left in the temporary directory in
    ssh_bootstrap: we'll executed it to start the main bootstrap process.

    """
    stdout_pipe = await (await parent.task.pipe(
        await parent.ram.malloc(Pipe))).read()
    async_stdout = await parent.make_afd(stdout_pipe.read, set_nonblock=True)
    child = await parent.clone()
    await child.task.inherit_fd(stdout_pipe.write).dup2(child.stdout)
    await child.task.inherit_fd(bootstrap_executable).dup2(child.stdin)
    child_process = await child.exec(ssh_command.args(ssh_bootstrap_script_contents))
    await stdout_pipe.write.close()
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
    done = await lines_buf.read_line()
    if done != b"done":
        raise Exception("socket binder violated protocol, got instead of done:", done)
    await async_stdout.close()
    logger.debug("socket bootstrap done, got tmp path %s", tmp_path_bytes)
    yield tmp_path_bytes
    await child_process.check()

async def ssh_forward(thread: Thread, ssh_command: SSHCommand,
                      local_path: Path, remote_path: str) -> AsyncChildProcess:
    "Forward Unix socket connections to local_path to the socket at remote_path, over ssh"
    stdout_pipe = await (await thread.task.pipe(
        await thread.ram.malloc(Pipe))).read()
    async_stdout = await thread.make_afd(stdout_pipe.read, set_nonblock=True)
    child = await thread.clone()
    await child.task.inherit_fd(stdout_pipe.write).dup2(child.stdout)
    await child.task.chdir(await thread.ptr(local_path.parent))
    child_process = await child.exec(ssh_command.local_forward(
        "./" + local_path.name, remote_path,
    # TODO I optimistically assume that I'll have established a
    # connection through the tunnel before 1 minute has passed;
    # that connection will then keep the tunnel open.
    ).args("-n", "echo forwarded; exec sleep 60"))
    lines_buf = AsyncReadBuffer(async_stdout)
    forwarded = await lines_buf.read_line()
    if forwarded != b"forwarded":
        raise Exception("ssh forwarding violated protocol, got instead of forwarded:", forwarded)
    await async_stdout.close()
    return child_process

async def ssh_bootstrap(
        parent: Thread,
        # the actual ssh command to run
        ssh_command: SSHCommand,
        # the local path we'll use for the socket
        local_socket_path: Path,
        # the directory we're bootstrapping out of
        tmp_path_bytes: bytes,
) -> t.Tuple[AsyncChildProcess, Thread]:
    "Over ssh, run the bootstrap executable, "
    # identify local path
    local_data_addr = await parent.ram.ptr(
        await SockaddrUn.from_path(parent, local_socket_path))
    # start port forwarding; we'll just leak this process, no big deal
    # TODO we shouldn't leak processes; we should be GCing processes at some point
    forward_child_process = await ssh_forward(
        parent, ssh_command, local_socket_path, (tmp_path_bytes + b"/data").decode())
    # start bootstrap
    bootstrap_thread = await parent.clone()
    bootstrap_child_process = await bootstrap_thread.exec(ssh_command.args(
        "-n", f"cd {tmp_path_bytes.decode()}; exec ./bootstrap rsyscall"
    ))
    # TODO should unlink the bootstrap after I'm done execing.
    # it would be better if sh supported fexecve, then I could unlink it before I exec...
    # Connect to local socket 4 times
    async def make_async_connection() -> AsyncFileDescriptor:
        sock = await parent.make_afd(await parent.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        await sock.connect(local_data_addr)
        return sock
    async_local_syscall_sock = await make_async_connection()
    async_local_data_sock = await make_async_connection()
    # Read description off of the data sock
    describe_buf = AsyncReadBuffer(async_local_data_sock)
    describe_struct = await describe_buf.read_cffi('struct rsyscall_bootstrap')
    new_pid = describe_struct.pid
    environ = await describe_buf.read_envp(describe_struct.envp_count)
    # Build the new task!
    new_address_space = far.AddressSpace(new_pid)
    # TODO the pid namespace will probably be common for all connections...
    # TODO we should get this from the SSHHost, this is usually going
    # to be common for all connections and we should express that
    new_pid_namespace = far.PidNamespace(new_pid)
    new_process = near.Process(new_pid)
    new_base_task = Task(
        new_process, handle.FDTable(new_pid), new_address_space,
        new_pid_namespace,
    )
    handle_remote_syscall_fd = new_base_task.make_fd_handle(near.FileDescriptor(describe_struct.syscall_sock))
    new_base_task.sysif = SyscallConnection(
        logger.getChild(str(new_process)),
        async_local_syscall_sock, async_local_syscall_sock,
        handle_remote_syscall_fd, handle_remote_syscall_fd,
    )
    handle_remote_data_fd = new_base_task.make_fd_handle(near.FileDescriptor(describe_struct.data_sock))
    handle_listening_fd = new_base_task.make_fd_handle(near.FileDescriptor(describe_struct.listening_sock))
    new_allocator = memory.AllocatorClient.make_allocator(new_base_task)
    new_transport = SocketMemoryTransport(async_local_data_sock, handle_remote_data_fd)
    # we don't inherit SignalMask; we assume ssh zeroes the sigmask before starting us
    new_ram = RAM(new_base_task, new_transport, new_allocator)
    epoller = await Epoller.make_root(new_ram, new_base_task)
    child_monitor = await ChildProcessMonitor.make(new_ram, new_base_task, epoller)
    await handle_listening_fd.fcntl(F.SETFL, O.NONBLOCK)
    connection = ListeningConnection(
        parent.task, parent.ram, parent.epoller,
        local_data_addr,
        new_base_task, new_ram,
        await AsyncFileDescriptor.make(epoller, new_ram, handle_listening_fd),
    )
    new_thread = Thread(
        task=new_base_task,
        ram=new_ram,
        connection=connection,
        loader=NativeLoader.make_from_symbols(new_base_task, describe_struct.symbols),
        epoller=epoller,
        child_monitor=child_monitor,
        environ=Environment.make_from_environ(new_base_task, new_ram, environ),
        stdin=new_base_task.make_fd_handle(near.FileDescriptor(0)),
        stdout=new_base_task.make_fd_handle(near.FileDescriptor(1)),
        stderr=new_base_task.make_fd_handle(near.FileDescriptor(2)),
    )
    return bootstrap_child_process, new_thread

@dataclass
class SSHDExecutables:
    """A standalone representation of the executables needed to run sshd

    This is not really a user-facing class; see SSHExecutables.

    """
    ssh_keygen: Command
    sshd: SSHDCommand

    @classmethod
    async def with_nix(cls, thread: Thread) -> SSHDExecutables:
        import rsyscall._nixdeps.openssh
        ssh_path = await nix.deploy(thread, rsyscall._nixdeps.openssh.closure)
        ssh_keygen = ssh_path.bin('ssh-keygen')
        sshd = SSHDCommand.make(ssh_path/"bin"/"sshd")
        return SSHDExecutables(ssh_keygen, sshd)

async def make_local_ssh_from_executables(thread: Thread,
                                          executables: SSHExecutables, sshd_executables: SSHDExecutables) -> SSHHost:
    "Make an SSHHost which just sshs to localhost; useful for testing"
    ssh_keygen = sshd_executables.ssh_keygen
    sshd = sshd_executables.sshd

    keygen_command = ssh_keygen.args('-b', '1024', '-q', '-N', '', '-C', '', '-f', 'key')
    keygen_thread = await thread.clone()
    # ugh, we have to make a directory because ssh-keygen really wants to output to a directory
    async with (await mkdtemp(thread)) as tmpdir:
        await keygen_thread.task.chdir(await keygen_thread.ram.ptr(tmpdir))
        await (await keygen_thread.exec(keygen_command)).waitpid(W.EXITED)
        privkey_file = await thread.task.open(await thread.ram.ptr(tmpdir/'key'), O.RDONLY)
        pubkey_file = await thread.task.open(await thread.ram.ptr(tmpdir/'key.pub'), O.RDONLY)
    def to_host(ssh: SSHCommand, privkey_file=privkey_file, pubkey_file=pubkey_file) -> SSHCommand:
        privkey = privkey_file.as_proc_path()
        pubkey = pubkey_file.as_proc_path()
        sshd_command = sshd.args(
            '-i', '-e', '-f', '/dev/null',
        ).sshd_options({
            'LogLevel': 'INFO',
            'HostKey': privkey,
            'AuthorizedKeysFile': pubkey,
            'StrictModes': 'no',
            'PrintLastLog': 'no',
            'PrintMotd': 'no',
            'UsePrivilegeSeparation': 'no',
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
async def make_ssh_host(thread: Thread, to_host: t.Callable[[SSHCommand], SSHCommand]) -> SSHHost:
    ssh = await SSHExecutables.with_nix(thread)
    return ssh.host(to_host)

async def make_local_ssh(thread: Thread) -> SSHHost:
    "Look up the ssh executables and return an SSHHost which sshs to localhost; useful for testing"
    ssh = await SSHExecutables.with_nix(thread)
    sshd = await SSHDExecutables.with_nix(thread)
    return (await make_local_ssh_from_executables(thread, ssh, sshd))

