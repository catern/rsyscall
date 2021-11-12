"""A thread-creating stub which can be exec'd by other programs which pass down stdin

The user creates an arbitrary Command which eventually execs rsyscall-stdin-bootstrap, and
calls stdin_bootstrap with it; stdin_bootstrap runs the command and returns a thread
created from the eventually-exec'd rsyscall-stdin-bootstrap.

This is useful for sudo and similar programs; we can pass a Command which runs "sudo
rsyscall-stdin-bootstrap", and thereby get a Thread with different privileges.

"""
import typing as t
from dataclasses import dataclass
from rsyscall.command import Command
from rsyscall.environ import Environment
from rsyscall.epoller import Epoller, AsyncReadBuffer
from rsyscall.handle import WrittenPointer, Task
from rsyscall.thread import Thread
from rsyscall.loader import NativeLoader
from rsyscall.memory.ram import RAM
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.tasks.connection import SyscallConnection
import logging
import rsyscall.far as far
import rsyscall.handle as handle
import rsyscall.memory.allocator as memory
import rsyscall.near.types as near
import rsyscall.nix as nix
import struct
import trio

from rsyscall.path import Path
from rsyscall.sched import CLONE
from rsyscall.signal import SIG, SignalBlock
from rsyscall.sys.mman import MFD
from rsyscall.sys.socket import SOCK, AF, SendmsgFlags, Socketpair, SendMsghdr, CmsgList, CmsgSCMRights
from rsyscall.sys.uio import IovecList

__all__ = [
    "stdin_bootstrap_path_with_nix",
    "stdin_bootstrap",
]

logger = logging.getLogger(__name__)

async def stdin_bootstrap_path_with_nix(thread: Thread) -> Path:
    """Get the path to the rsyscall-stdin-bootstrap executable.

    We return a Path rather than a Command because the typical usage
    of this path will be to pass it as an argument to some other
    command, such as sudo.

    """
    import rsyscall._nixdeps.librsyscall
    rsyscall_path = await nix.deploy(thread, rsyscall._nixdeps.librsyscall.closure)
    return rsyscall_path/"libexec"/"rsyscall"/"rsyscall-stdin-bootstrap"

async def stdin_bootstrap(
        parent: Thread,
        bootstrap_command: Command,
) -> t.Tuple[AsyncChildProcess, Thread]:
    """Create a thread from running an arbitrary command which must run rsyscall-stdin-bootstrap

    bootstrap_command can be any arbitrary command, but it must eventually exec
    rsyscall-stdin-bootstrap, and pass down stdin when it does.

    We'll clone and exec bootstrap_command, passing down a socketpair for stdin, and try to
    bootstrap over the other end of the socketpair. Once rsyscall-stdin-bootstrap starts,
    it will respond to our bootstrap and we'll create a new thread.

    """
    #### clone and exec into the bootstrap command
    # create the socketpair that will be used as stdin
    stdin_pair = await (await parent.task.socketpair(
        AF.UNIX, SOCK.STREAM, 0, await parent.ram.malloc(Socketpair))).read()
    parent_sock = stdin_pair.first
    child = await parent.clone()
    # set up stdin with socketpair
    await child.task.inherit_fd(stdin_pair.second).dup2(child.stdin)
    await stdin_pair.second.close()
    # exec
    child_process = await child.exec(bootstrap_command)
    #### set up all the fds we'll want to pass over
    # the basic connections
    [(access_syscall_sock, passed_syscall_sock),
     (access_data_sock, passed_data_sock)] = await parent.open_async_channels(2)
    # send the fds to the new process
    connection_fd, make_connection = await parent.connection.prep_fd_transfer()
    async def sendmsg_op(sem: RAM) -> WrittenPointer[SendMsghdr]:
        iovec = await sem.ptr(IovecList([await sem.malloc(bytes, 1)]))
        cmsgs = await sem.ptr(CmsgList([CmsgSCMRights([
            passed_syscall_sock, passed_data_sock, connection_fd])]))
        return await sem.ptr(SendMsghdr(None, iovec, cmsgs))
    _, [] = await parent_sock.sendmsg(await parent.ram.perform_batch(sendmsg_op), SendmsgFlags.NONE)
    # close our reference to fds that only the new process needs
    await passed_syscall_sock.close()
    await passed_data_sock.close()
    # close the socketpair
    await parent_sock.close()
    #### read describe to get all the information we need from the new process
    describe_buf = AsyncReadBuffer(access_data_sock)
    describe_struct = await describe_buf.read_cffi('struct rsyscall_stdin_bootstrap')
    environ = await describe_buf.read_envp(describe_struct.envp_count)
    #### build the new task
    pid = describe_struct.pid
    fd_table = handle.FDTable(pid)
    address_space = far.AddressSpace(pid)
    # we assume pid namespace is shared
    # TODO include namespace inode numbers numbers in describe
    # note: if we start dealing with namespace numbers then we need to
    # have a Kernel namespace which tells us which kernel we get those
    # numbers from.
    # oh hey we can conveniently dump the inode numbers with getdents!
    pidns = parent.task.pidns
    process = near.Process(pid)
    base_task = Task(process, fd_table, address_space, pidns)
    remote_syscall_fd = base_task.make_fd_handle(near.FileDescriptor(describe_struct.syscall_fd))
    base_task.sysif = SyscallConnection(
        logger.getChild(str(process)),
        access_syscall_sock, access_syscall_sock,
        remote_syscall_fd, remote_syscall_fd,
    )
    allocator = memory.AllocatorClient.make_allocator(base_task)
    # we assume our SignalMask is zero'd before being started, so we don't inherit it
    ram = RAM(base_task,
               SocketMemoryTransport(access_data_sock,
                                     base_task.make_fd_handle(near.FileDescriptor(describe_struct.data_fd))),
               allocator)
    # TODO I think I can maybe elide creating this epollcenter and instead inherit it or share it, maybe?
    epoller = await Epoller.make_root(ram, base_task)
    child_monitor = await ChildProcessMonitor.make(ram, base_task, epoller)
    connection = make_connection(base_task, ram,
                                 base_task.make_fd_handle(near.FileDescriptor(describe_struct.connecting_fd)))
    new_parent = Thread(
        task=base_task,
        ram=ram,
        connection=connection,
        loader=NativeLoader.make_from_symbols(base_task, describe_struct.symbols),
        epoller=epoller,
        child_monitor=child_monitor,
        environ=Environment.make_from_environ(base_task, ram, environ),
        stdin=base_task.make_fd_handle(near.FileDescriptor(0)),
        stdout=base_task.make_fd_handle(near.FileDescriptor(1)),
        stderr=base_task.make_fd_handle(near.FileDescriptor(2)),
    )
    return child_process, new_parent
