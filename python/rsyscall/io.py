from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import types
import traceback
import pathlib

import math


import rsyscall.handle as handle
import rsyscall.handle
from rsyscall.handle import T_pointer, Stack, WrittenPointer, MemoryMapping, FutexNode, Arg, ThreadProcess, MemoryGateway, Pointer
import rsyscall.far as far
import rsyscall.near as near
from rsyscall.struct import T_struct, T_fixed_size, Bytes, Int32, Serializer, Struct
import rsyscall.batch as batch
from rsyscall.batch import BatchSemantics

import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.loader import Trampoline, ProcessResources
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.tasks.fork import spawn_rsyscall_thread, RsyscallConnection, SyscallResponse
from rsyscall.tasks.common import raise_if_error, log_syscall

from rsyscall.sys.socket import AF, SOCK, SOL, SO, Address, GenericSockaddr, SendmsgFlags, RecvmsgFlags, Sockbuf
from rsyscall.fcntl import AT, O, F
from rsyscall.sys.socket import T_addr
from rsyscall.sys.mount import MS
from rsyscall.sys.un import SockaddrUn, PathTooLongError
from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.sys.epoll import EpollEvent, EpollEventList, EPOLL, EPOLL_CTL, EpollFlag
from rsyscall.sys.wait import W, ChildEvent
from rsyscall.sys.memfd import MFD
from rsyscall.sys.signalfd import SFD, SignalfdSiginfo
from rsyscall.sys.inotify import InotifyFlag
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sched import UnshareFlag, CLONE
from rsyscall.signal import HowSIG, Sigaction, Sighandler, Signals, Sigset, Siginfo
from rsyscall.signal import SignalBlock
from rsyscall.linux.dirent import Dirent, DirentList
from rsyscall.unistd import SEEK
from rsyscall.network.connection import Connection

import random
import string
import abc
import prctl
import socket
import abc
import sys
import os
import typing as t
import struct
import array
import trio
import signal
from dataclasses import dataclass, field
import logging
import fcntl
import errno
import enum
import contextlib
import inspect
logger = logging.getLogger(__name__)

T = t.TypeVar('T')
class Task(RAM):
    def __init__(self,
                 base_: handle.Task,
                 transport: handle.MemoryTransport,
                 allocator: memory.AllocatorClient,
    ) -> None:
        super().__init__(base_, transport, allocator)
        self.base = base_

    def root(self) -> Path:
        return Path(self, handle.Path("/"))

    def cwd(self) -> Path:
        return Path(self, handle.Path("."))

    async def close(self):
        await self.base.sysif.close_interface()

    async def mount(self, source: bytes, target: bytes,
                    filesystemtype: bytes, mountflags: MS,
                    data: bytes) -> None:
        def op(sem: batch.BatchSemantics) -> t.Tuple[
                WrittenPointer[Arg], WrittenPointer[Arg], WrittenPointer[Arg], WrittenPointer[Arg]]:
            return (
                sem.to_pointer(Arg(source)),
                sem.to_pointer(Arg(target)),
                sem.to_pointer(Arg(filesystemtype)),
                sem.to_pointer(Arg(data)),
            )
        source_ptr, target_ptr, filesystemtype_ptr, data_ptr = await self.perform_batch(op)
        await self.base.mount(source_ptr, target_ptr, filesystemtype_ptr, mountflags, data_ptr)

    async def exit(self, status: int) -> None:
        await self.base.exit(status)
        await self.close()

    def _make_fd(self, num: int) -> MemFileDescriptor:
        return self.make_fd(near.FileDescriptor(num))

    def make_fd(self, fd: near.FileDescriptor) -> MemFileDescriptor:
        return FileDescriptor(self, self.base.make_fd_handle(fd))

    # TODO maybe we'll put these calls as methods on a MemoryAbstractor,
    # and they'll take an handle.FileDescriptor.
    # then we'll directly have StandardTask contain both Task and MemoryAbstractor?
    async def pipe(self, flags=O.CLOEXEC) -> Pipe:
        pipe = await (await self.base.pipe(await self.malloc_struct(handle.Pipe), O.CLOEXEC)).read()
        return Pipe(FileDescriptor(self, pipe.read),
                    FileDescriptor(self, pipe.write))

    async def socketpair(self, domain: AF, type: SOCK, protocol: int) -> t.Tuple[FileDescriptor, FileDescriptor]:
        pair = await (await self.base.socketpair(domain, type, protocol, await self.malloc_struct(handle.FDPair))).read()
        return (FileDescriptor(self, pair.first),
                FileDescriptor(self, pair.second))

    async def socket_unix(self, type: SOCK, protocol: int=0, cloexec=True) -> MemFileDescriptor:
        sockfd = await self.base.socket(AF.UNIX, type, protocol, cloexec=cloexec)
        return FileDescriptor(self, sockfd)

    async def make_epoll_center(self) -> EpollCenter:
        epfd = await self.base.epoll_create(EpollFlag.CLOEXEC)
        if self.base.sysif.activity_fd is not None:
            activity_fd = self.base.make_fd_handle(self.base.sysif.activity_fd)
            epoll_center = await EpollCenter.make(self, epfd, None, activity_fd)
        else:
            # TODO this is a pretty low-level detail, not sure where is the right place to do this
            async def wait_readable():
                logger.debug("wait_readable(%s)", epfd.near.number)
                await trio.hazmat.wait_readable(epfd.near.number)
            epoll_center = await EpollCenter.make(self, epfd, wait_readable, None)
        return epoll_center

class MemFileDescriptor:
    "A file descriptor, plus a task to access it from, plus the file object underlying the descriptor."
    task: Task
    def __init__(self, task: Task, handle: handle.FileDescriptor) -> None:
        self.task = task
        self.handle = handle
        self.open = True

    async def aclose(self):
        if self.open:
            await self.handle.close()
        else:
            pass

    def __str__(self) -> str:
        return f'FD({self.task}, {self.handle})'

    async def __aenter__(self) -> 'MemFileDescriptor':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    async def invalidate(self) -> None:
        await self.handle.invalidate()
        self.open = False

    async def close(self):
        await self.handle.close()
        self.open = False

    def for_task(self, task: handle.Task) -> 'MemFileDescriptor':
        if self.open:
            return self.__class__(self.task, task.make_fd_handle(self.handle))
        else:
            raise Exception("file descriptor already closed")

    def move(self, task: handle.Task) -> 'MemFileDescriptor':
        if self.open:
            return self.__class__(self.task, self.handle.move(task))
        else:
            raise Exception("file descriptor already closed")

    async def copy_from(self, source: handle.FileDescriptor, flags=0) -> None:
        if self.handle.task.fd_table != source.task.fd_table:
            raise Exception("two fds are not in the same file descriptor tables",
                            self.handle.task.fd_table, source.task.fd_table)
        if self.handle.near == source.near:
            return
        await source.dup3(self.handle, flags)

    async def replace_with(self, source: handle.FileDescriptor, flags=0) -> None:
        await self.copy_from(source)
        await source.invalidate()

    async def set_nonblock(self) -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        await self.handle.fcntl(F.SETFL, O.NONBLOCK)

    async def read(self, count: int=4096) -> bytes:
        valid, _ = await self.handle.read(await self.task.malloc_type(Bytes, count))
        return await valid.read()

    async def write(self, data: bytes) -> int:
        written, _ = await self.handle.write(await self.task.to_pointer(Bytes(data)))
        return written.bytesize()

    async def write_all(self, data: bytes) -> None:
        remaining: handle.Pointer = await self.task.to_pointer(Bytes(data))
        while remaining.bytesize() > 0:
            written, remaining = await self.handle.write(remaining)

    async def getdents(self, count: int=4096) -> DirentList:
        valid, _ = await self.handle.getdents(await self.task.malloc_type(DirentList, count))
        return await valid.read()

    async def bind(self, addr: Address) -> None:
        await self.handle.bind(await self.task.to_pointer(addr))

    async def connect(self, addr: Address) -> None:
        await self.handle.connect(await self.task.to_pointer(addr))

    async def listen(self, backlog: int) -> None:
        await self.handle.listen(backlog)

    async def setsockopt(self, level: int, optname: int, optval: t.Union[bytes, int]) -> None:
        if isinstance(optval, bytes):
            ptr: handle.Pointer = await self.task.to_pointer(Bytes(optval))
        else:
            ptr = await self.task.to_pointer(Int32(optval))
        await self.handle.setsockopt(level, optname, ptr)

    async def getsockname(self) -> Address:
        written_sockbuf = await self.task.to_pointer(Sockbuf(await self.task.malloc_struct(GenericSockaddr)))
        sockbuf = await self.handle.getsockname(written_sockbuf)
        return (await (await sockbuf.read()).buf.read()).parse()

    async def getpeername(self) -> Address:
        written_sockbuf = await self.task.to_pointer(Sockbuf(await self.task.malloc_struct(GenericSockaddr)))
        sockbuf = await self.handle.getpeername(written_sockbuf)
        return (await (await sockbuf.read()).buf.read()).parse()

    async def getsockopt(self, level: int, optname: int, optlen: int) -> bytes:
        written_sockbuf = await self.task.to_pointer(Sockbuf(await self.task.malloc_type(Bytes, optlen)))
        sockbuf = await self.handle.getsockopt(level, optname, written_sockbuf)
        return (await (await sockbuf.read()).buf.read())

    async def accept(self, flags: SOCK) -> t.Tuple[FileDescriptor, Address]:
        written_sockbuf = await self.task.to_pointer(Sockbuf(await self.task.malloc_struct(GenericSockaddr)))
        fd, sockbuf = await self.handle.accept(flags, written_sockbuf)
        addr = (await (await sockbuf.read()).buf.read()).parse()
        return FileDescriptor(self.task, fd), addr

FileDescriptor = MemFileDescriptor

class Path(rsyscall.path.PathLike):
    "This is a convenient combination of a Path and a Task to perform serialization."
    def __init__(self, task: Task, handle: rsyscall.path.Path) -> None:
        self.task = task
        self.handle = handle
        # we cache the pointer to the serialized path
        self._ptr: t.Optional[rsyscall.handle.WrittenPointer[rsyscall.path.Path]] = None

    def with_task(self, task: Task) -> Path:
        return Path(task, self.handle)

    @property
    def parent(self) -> Path:
        return Path(self.task, self.handle.parent)

    @property
    def name(self) -> str:
        return self.handle.name

    async def to_pointer(self) -> rsyscall.handle.WrittenPointer[rsyscall.path.Path]:
        if self._ptr is None:
            self._ptr = await self.task.to_pointer(self.handle)
        return self._ptr

    async def mkdir(self, mode=0o777) -> Path:
        try:
            await self.task.base.mkdir(await self.to_pointer(), mode)
        except FileExistsError as e:
            raise FileExistsError(e.errno, e.strerror, self) from None
        return self

    async def open(self, flags: int, mode=0o644) -> FileDescriptor:
        """Open a path

        Note that this can block forever if we're opening a FIFO

        """
        fd = await self.task.base.open(await self.to_pointer(), flags, mode)
        return FileDescriptor(self.task, fd)

    async def open_directory(self) -> MemFileDescriptor:
        return (await self.open(O.DIRECTORY))

    async def open_path(self) -> MemFileDescriptor:
        return (await self.open(O.PATH))

    async def creat(self, mode=0o644) -> MemFileDescriptor:
        return await self.open(O.WRONLY|O.CREAT|O.TRUNC, mode)

    async def access(self, *, read=False, write=False, execute=False) -> bool:
        mode = 0
        if read:
            mode |= os.R_OK
        if write:
            mode |= os.W_OK
        if execute:
            mode |= os.X_OK
        # default to os.F_OK
        if mode == 0:
            mode = os.F_OK
        ptr = await self.to_pointer()
        try:
            await self.task.base.access(ptr, mode)
            return True
        except OSError:
            return False

    async def unlink(self, flags: int=0) -> None:
        await self.task.base.unlink(await self.to_pointer())

    async def rmdir(self) -> None:
        await self.task.base.rmdir(await self.to_pointer())

    async def link(self, oldpath: Path, flags: int=0) -> Path:
        "Create a hardlink at Path 'self' to the file at Path 'oldpath'"
        await self.task.base.link(await oldpath.to_pointer(), await self.to_pointer())
        return self

    async def symlink(self, target: t.Union[bytes, str, Path]) -> Path:
        "Create a symlink at Path 'self' pointing to the passed-in target"
        if isinstance(target, Path):
            target_ptr = await target.to_pointer()
        else:
            # TODO should write the bytes directly, rather than going through Path;
            # Path will canonicalize the bytes as a path, which isn't right
            target_ptr = await self.task.to_pointer(handle.Path(os.fsdecode(target)))
        await self.task.base.symlink(target_ptr, await self.to_pointer())
        return self

    async def rename(self, oldpath: Path, flags: int=0) -> Path:
        "Create a file at Path 'self' by renaming the file at Path 'oldpath'"
        await self.task.base.rename(await oldpath.to_pointer(), await self.to_pointer())
        return self

    async def readlink(self) -> Path:
        size = 4096
        valid, _ = await self.task.base.readlink(await self.to_pointer(),
                                                 await self.task.malloc_type(rsyscall.path.Path, size))
        if valid.bytesize() == size:
            # ext4 limits symlinks to this size, so let's just throw if it's larger;
            # we can add retry logic later if we ever need it
            raise Exception("symlink longer than 4096 bytes, giving up on readlinking it")
        # readlink doesn't append a null byte, so unfortunately we can't save this buffer and use it for later calls
        return Path(self.task, await valid.read())

    async def canonicalize(self) -> Path:
        async with (await self.open_path()) as f:
            return (await Path(self.task, f.handle.as_proc_path()).readlink())

    @contextlib.asynccontextmanager
    async def as_sockaddr_un(self) -> t.AsyncGenerator[SockaddrUn, None]:
        """Turn this path into a SockaddrUn, hacking around the 108 byte limit on socket addresses.

        If the passed path is too long to fit in an address, this function will open that path with
        O_PATH and return SockaddrUn("/proc/self/fd/n").

        """
        try:
            yield SockaddrUn.from_path(self)
        except PathTooLongError:
            async with (await self.open_path()) as fd:
                path = handle.Path("/proc/self/fd")/str(int(fd.handle.near))
                yield SockaddrUn.from_path(path)

    # to_bytes and from_bytes, kinda sketchy, hmm....
    # from_bytes will fail at runtime... whatever

    T = t.TypeVar('T', bound='Path')
    def __truediv__(self: T, key: t.Union[str, bytes, pathlib.PurePath]) -> T:
        if isinstance(key, bytes):
            key = os.fsdecode(key)
        return type(self)(self.task, self.handle/key)

    def __fspath__(self) -> str:
        return self.handle.__fspath__()

def random_string(k=8) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))

async def update_symlink(parent: Path, name: str, target: str) -> None:
    tmpname = name + ".updating." + random_string()
    tmppath = (parent/tmpname)
    await tmppath.symlink(target)
    await (parent/name).rename(tmppath)

async def robust_unix_bind(path: Path, sock: MemFileDescriptor) -> None:
    """Perform a Unix socket bind, hacking around the 108 byte limit on socket addresses.

    If the passed path is too long to fit in an address, this function will open the path's
    directory with O_PATH, and bind to /proc/self/fd/n/{pathname}; if that's still too long due to
    pathname being too long, this function will call robust_unix_bind_helper to bind to a temporary
    name and rename the resulting socket to pathname.

    If you are going to be binding to this path repeatedly, it's more efficient to open the
    directory with O_PATH and call robust_unix_bind_helper yourself, rather than call into this
    function.

    """
    try:
        addr = SockaddrUn.from_path(path)
    except PathTooLongError:
        # shrink the path by opening its parent directly as a dirfd
        async with (await path.parent.open_directory()) as dirfd:
            await bindat(sock, dirfd.handle, path.name)
    else:
        await sock.bind(addr)

async def bindat(sock: MemFileDescriptor, dirfd: handle.FileDescriptor, name: str) -> None:
    """Perform a Unix socket bind to dirfd/name

    TODO: This hack is actually semantically different from a normal direct bind: it's not
    atomic. That's tricky...

    """
    dir = Path(sock.task, handle.Path("/proc/self/fd")/str(int(dirfd.near)))
    path = dir/name
    try:
        addr = SockaddrUn.from_path(path)
    except PathTooLongError:
        # TODO retry if this name is used
        tmpname = ".temp_for_bindat." + random_string(k=16)
        tmppath = dir/tmpname
        await sock.bind(SockaddrUn.from_path(tmppath))
        await path.rename(tmppath)
    else:
        await sock.bind(addr)

async def robust_unix_connect(path: Path, sock: MemFileDescriptor) -> None:
    """Perform a Unix socket connect, hacking around the 108 byte limit on socket addresses.

    If the passed path is too long to fit in an address, this function will open that path with
    O_PATH and connect to /proc/self/fd/n.

    If you are going to be connecting to this path repeatedly, it's more efficient to open the path
    with O_PATH yourself rather than call into this function.

    """
    async with path.as_sockaddr_un() as addr:
        await sock.connect(addr)

async def spit(path: Path, text: t.Union[str, bytes], mode=0o644) -> Path:
    """Open a file, creating and truncating it, and write the passed text to it

    Probably shouldn't use this on FIFOs or anything.

    Returns the passed-in Path so this serves as a nice pseudo-constructor.

    """
    data = os.fsencode(text)
    async with (await path.creat(mode=mode)) as fd:
        while len(data) > 0:
            ret = await fd.write(data)
            data = data[ret:]
    return path

async def lookup_executable(paths: t.List[Path], name: bytes) -> Path:
    "Find an executable by this name in this list of paths"
    if b"/" in name:
        raise Exception("name should be a single path element without any / present")
    for path in paths:
        filename = path/name
        if (await filename.access(read=True, execute=True)):
            return filename
    raise Exception("executable not found", name)

async def which(stdtask: StandardTask, name: t.Union[str, bytes]) -> Command:
    "Find an executable by this name in PATH"
    namebytes = os.fsencode(name)
    executable_dirs: t.List[Path] = []
    for prefix in stdtask.environment[b"PATH"].split(b":"):
        executable_dirs.append(Path(stdtask.task, handle.Path(os.fsdecode(prefix))))
    executable_path = await lookup_executable(executable_dirs, namebytes)
    return Command(executable_path.handle, [namebytes], {})

async def write_user_mappings(task: Task, uid: int, gid: int,
                              in_namespace_uid: int=None, in_namespace_gid: int=None) -> None:
    if in_namespace_uid is None:
        in_namespace_uid = uid
    if in_namespace_gid is None:
        in_namespace_gid = gid
    root = task.root()

    uid_map = await (root/"proc"/"self"/"uid_map").open(O.WRONLY)
    await uid_map.write(f"{in_namespace_uid} {uid} 1\n".encode())
    await uid_map.invalidate()

    setgroups = await (root/"proc"/"self"/"setgroups").open(O.WRONLY)
    await setgroups.write(b"deny")
    await setgroups.invalidate()

    gid_map = await (root/"proc"/"self"/"gid_map").open(O.WRONLY)
    await gid_map.write(f"{in_namespace_gid} {gid} 1\n".encode())
    await gid_map.invalidate()

class StandardTask:
    def __init__(self,
                 access_task: Task,
                 access_epoller: EpollCenter,
                 access_connection: t.Optional[t.Tuple[Path, handle.FileDescriptor]],
                 connecting_task: Task,
                 # TODO we need to lock this, and the access_connection also.
                 # they are shared between processes...
                 connecting_connection: t.Tuple[handle.FileDescriptor, handle.FileDescriptor],
                 task: Task,
                 process_resources: ProcessResources,
                 epoller: EpollCenter,
                 child_monitor: ChildProcessMonitor,
                 environment: t.Dict[bytes, bytes],
                 stdin: MemFileDescriptor,
                 stdout: MemFileDescriptor,
                 stderr: MemFileDescriptor,
    ) -> None:
        self.access_task = access_task
        self.access_epoller = access_epoller
        self.access_connection = access_connection
        self.connecting_task = connecting_task
        self.connecting_connection = connecting_connection
        self.task = task
        self.process = process_resources
        self.epoller = epoller
        self.child_monitor = child_monitor
        self.environment = environment
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.sh = Command(handle.Path("/bin/sh"), ['sh'], {})
        self.tmpdir = handle.Path(os.fsdecode(self.environment.get(b"TMPDIR", b"/tmp")))

    async def mkdtemp(self, prefix: str="mkdtemp") -> 'TemporaryDirectory':
        parent = Path(self.task, self.tmpdir)
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = (prefix+"."+random_suffix).encode()
        await (parent/name).mkdir(mode=0o700)
        return TemporaryDirectory(self, parent, name)

    async def make_afd(self, fd: handle.FileDescriptor, nonblock: bool=False) -> AsyncFileDescriptor:
        return await AsyncFileDescriptor.make_handle(self.epoller, self.task, fd, is_nonblock=nonblock)

    async def make_async_connections(self, count: int) -> t.List[
            t.Tuple[AsyncFileDescriptor, handle.FileDescriptor]
    ]:
        conns = await self.make_connections(count)
        access_socks, local_socks = zip(*conns)
        async_access_socks = [await AsyncFileDescriptor.make_handle(self.access_epoller, self.access_task, sock)
                              for sock in access_socks]
        return list(zip(async_access_socks, local_socks))

    async def make_connections(self, count: int) -> t.List[
            t.Tuple[handle.FileDescriptor, handle.FileDescriptor]
    ]:
        return (await make_connections(
            self.access_task, self.access_connection,
            self.connecting_task, self.connecting_connection,
            self.task, count))

    async def fork(self, newuser=False, newpid=False, fs=True, sighand=True) -> RsyscallThread:
        [(access_sock, remote_sock)] = await self.make_async_connections(1)
        base_task = await spawn_rsyscall_thread(
            self.task, self.task.base,
            access_sock, remote_sock,
            self.child_monitor, self.process,
            newuser=newuser, newpid=newpid, fs=fs, sighand=sighand,
        )
        task = Task(base_task,
                    # We don't inherit the transport because it leads to a deadlock:
                    # If when a child task calls transport.read, it performs a syscall in the child task,
                    # then the parent task will need to call waitid to monitor the child task during the syscall,
                    # which will in turn need to also call transport.read.
                    # But the child is already using the transport and holding the lock,
                    # so the parent will block forever on taking the lock,
                    # and child's read syscall will never complete.
                    self.task.transport,
                    self.task.allocator.inherit(base_task),
        )
        await remote_sock.invalidate()
        if newuser:
            # hack, we should really track the [ug]id ahead of this so we don't have to get it
            # we have to get the [ug]id from the parent because it will fail in the child
            uid = await self.task.base.getuid()
            gid = await self.task.base.getgid()
            await write_user_mappings(task, uid, gid)
        if newpid or self.child_monitor.is_reaper:
            # if the new process is pid 1, then CLONE_PARENT isn't allowed so we can't use inherit_to_child.
            # if we are a reaper, than we don't want our child CLONE_PARENTing to us, so we can't use inherit_to_child.
            # in both cases we just fall back to making a new ChildProcessMonitor for the child.
            epoller = await task.make_epoll_center()
            # this signal is already blocked, we inherited the block, um... I guess...
            # TODO handle this more formally
            signal_block = SignalBlock(task.base, await task.to_pointer(Sigset({signal.SIGCHLD})))
            child_monitor = await ChildProcessMonitor.make(task, task.base,
                                                           epoller, signal_block=signal_block, is_reaper=newpid)
        else:
            epoller = self.epoller.inherit(task)
            child_monitor = self.child_monitor.inherit_to_child(task.base)
        stdtask = StandardTask(
            self.access_task, self.access_epoller, self.access_connection,
            self.connecting_task,
            (self.connecting_connection[0], task.base.make_fd_handle(self.connecting_connection[1])),
            task, 
            self.process,
            epoller, child_monitor,
            {**self.environment},
            stdin=self.stdin.for_task(task.base),
            stdout=self.stdout.for_task(task.base),
            stderr=self.stderr.for_task(task.base),
        )
        return RsyscallThread(stdtask, self.child_monitor)

    async def run(self, command: Command, check=True,
                  *, task_status=trio.TASK_STATUS_IGNORED) -> ChildEvent:
        thread = await self.fork(fs=False)
        child = await command.exec(thread)
        task_status.started(child)
        exit_event = await child.wait_for_exit()
        if check:
            exit_event.check()
        return exit_event

    async def unshare_files(self, going_to_exec=False) -> None:
        """Unshare the file descriptor table.

        Set going_to_exec to True if you are about to exec with this task; then we'll skip the
        manual CLOEXEC in userspace that we have to do to avoid keeping stray references around.

        TODO maybe this should return an object that lets us unset CLOEXEC on things?
        """
        async def do_unshare(close_in_old_space: t.List[near.FileDescriptor],
                             copy_to_new_space: t.List[near.FileDescriptor]) -> None:
            await unshare_files(self.task, self.process,
                                close_in_old_space, copy_to_new_space, going_to_exec)
        await self.task.base.unshare_files(do_unshare)

    async def unshare_files_and_replace(self, mapping: t.Dict[handle.FileDescriptor, handle.FileDescriptor],
                                        going_to_exec=False) -> None:
        mapping = {
            # we maybe_copy the key because we need to have the only handle to it in the task,
            # which we'll then consume through dup3.
            key.maybe_copy(self.task.base):
            # we for_task the value so that we get a copy of it, which we then explicitly invalidate;
            # this means if we had the only reference to the fd passed into us as an expression,
            # we will close that fd - nice.
            val.for_task(self.task.base)
            for key, val in mapping.items()}
        await self.unshare_files(going_to_exec=going_to_exec)
        for dest, source in mapping.items():
            await source.dup3(dest, 0)
            await source.invalidate()

    async def unshare_user(self,
                           in_namespace_uid: int=None, in_namespace_gid: int=None) -> None:
        uid = await self.task.base.getuid()
        gid = await self.task.base.getgid()
        await self.task.base.unshare_user()
        await write_user_mappings(self.task, uid, gid,
                                  in_namespace_uid=in_namespace_uid, in_namespace_gid=in_namespace_gid)

    async def unshare_net(self) -> None:
        await self.task.base.unshare_net()

    async def setns_user(self, fd: handle.FileDescriptor) -> None:
        await self.task.base.setns_user(fd)

    async def unshare_mount(self) -> None:
        await rsyscall.near.unshare(self.task.base.sysif, UnshareFlag.NEWNS)

    async def setns_mount(self, fd: handle.FileDescriptor) -> None:
        fd.check_is_for(self.task.base)
        await fd.setns(UnshareFlag.NEWNS)

    async def exit(self, status) -> None:
        await self.task.exit(0)

    async def close(self) -> None:
        await self.task.close()

    async def __aenter__(self) -> 'StandardTask':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class TemporaryDirectory:
    path: Path
    def __init__(self, stdtask: StandardTask, parent: Path, name: bytes) -> None:
        self.stdtask = stdtask
        self.parent = parent
        self.name = name
        self.path = parent/name

    async def cleanup(self) -> None:
        # TODO would be nice if not sharing the fs information gave us a cap to chdir
        cleanup_thread = await self.stdtask.fork(fs=False)
        async with cleanup_thread:
            await cleanup_thread.stdtask.task.base.chdir(await self.parent.to_pointer())
            name = os.fsdecode(self.name)
            child = await cleanup_thread.exec(self.stdtask.sh.args(
                '-c', f"chmod -R +w -- {name} && rm -rf -- {name}"))
            await child.check()

    async def __aenter__(self) -> 'Path':
        return self.path

    async def __aexit__(self, *args, **kwargs):
        await self.cleanup()

class RsyscallInterface(near.SyscallInterface):
    """An rsyscall connection to a task that is not our child.

    For correctness, we should ensure that we'll get HUP/EOF if the task has
    exited and therefore will never respond. This is most easily achieved by
    making sure that the fds keeping the other end of the RsyscallConnection
    open, are only held by one task, and so will be closed when the task
    exits. Note, though, that that requires that the task be in an unshared file
    descriptor space.

    """
    def __init__(self, rsyscall_connection: RsyscallConnection,
                 # usually the same pid that's inside the namespaces
                 identifier_process: near.Process,
                 activity_fd: near.FileDescriptor) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.logger = logging.getLogger(f"rsyscall.RsyscallConnection.{identifier_process.id}")
        self.identifier_process = identifier_process
        self.activity_fd = activity_fd
        # these are needed so that we don't accidentally close them when doing a do_cloexec_except
        self.infd: handle.FileDescriptor
        self.outfd: handle.FileDescriptor
        self.request_lock = trio.Lock()
        self.pending_responses: t.List[SyscallResponse] = []
        self.running: trio.Event = None

    def store_remote_side_handles(self, infd: handle.FileDescriptor, outfd: handle.FileDescriptor) -> None:
        self.infd = infd
        self.outfd = outfd

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def _process_response_for(self, response: SyscallResponse) -> None:
        try:
            ret = await self.rsyscall_connection.read_response()
            raise_if_error(ret)
        except Exception as e:
            response.set_exception(e)
        else:
            response.set_result(ret)

    async def _process_one_response_direct(self) -> None:
        if len(self.pending_responses) == 0:
            raise Exception("somehow we are trying to process a syscall response, when there are no pending syscalls.")
        next = self.pending_responses[0]
        await self._process_response_for(next)
        self.pending_responses = self.pending_responses[1:]

    async def _process_one_response(self) -> None:
        if self.running is not None:
            await self.running.wait()
        else:
            running = trio.Event()
            self.running = running
            try:
                await self._process_one_response_direct()
            finally:
                self.running = None
                running.set()

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        async with self.request_lock:
            log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
            await self.rsyscall_connection.write_request(
                number,
                arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        response = SyscallResponse(self._process_one_response)
        self.pending_responses.append(response)
        return response

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            # we must not be interrupted while reading the response - we need to return
            # the response so that our parent can deal with the state change we created.
            with trio.CancelScope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

async def do_cloexec_except(task: Task, process_resources: ProcessResources,
                            excluded_fds: t.Iterable[near.FileDescriptor]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    async def op(sem: batch.BatchSemantics) -> t.Tuple[t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]],
                                                       handle.Pointer[Siginfo]]:
        fd_array = array.array('i', [int(fd) for fd in excluded_fds])
        fd_array_ptr = sem.to_pointer(Bytes(fd_array.tobytes()))
        stack_value = process_resources.make_trampoline_stack(Trampoline(
            process_resources.do_cloexec_func, [fd_array_ptr, len(fd_array)]))
        stack_buf = sem.malloc_type(handle.Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        siginfo_buf = sem.malloc_struct(Siginfo)
        return stack, siginfo_buf
    stack, siginfo_buf = await task.perform_async_batch(op)
    process = await task.base.clone(CLONE.VM|CLONE.FILES, stack, ptid=None, ctid=None, newtls=None)
    await process.waitid(W.ALL|W.EXITED, siginfo_buf)
    child_event = await process.read_event()
    if not child_event.clean():
        raise Exception("cloexec function child died!", child_event)

async def unshare_files(
        task: Task, process_resources: ProcessResources,
        close_in_old_space: t.List[near.FileDescriptor],
        copy_to_new_space: t.List[near.FileDescriptor],
        going_to_exec: bool,
) -> None:
    async def op(sem: batch.BatchSemantics) -> t.Tuple[t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]],
                                                       handle.Pointer[Siginfo]]:
        fd_array = array.array('i', [int(fd) for fd in close_in_old_space])
        fd_array_ptr = sem.to_pointer(Bytes(fd_array.tobytes()))
        stack_value = process_resources.make_trampoline_stack(Trampoline(
            process_resources.stop_then_close_func, [fd_array_ptr, len(fd_array)]))
        stack_buf = sem.malloc_type(handle.Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        siginfo_buf = sem.malloc_struct(Siginfo)
        return stack, siginfo_buf
    stack, siginfo_buf = await task.perform_async_batch(op)
    process = await task.base.clone(CLONE.VM|CLONE.FILES|CLONE.FS|CLONE.IO|CLONE.SIGHAND|CLONE.SYSVSEM,
                                    stack, ptid=None, ctid=None, newtls=None)
    await process.waitid(W.ALL|W.STOPPED|W.EXITED, siginfo_buf)
    event = await process.read_event()
    if event.died():
        raise Exception("stop_then_close task died unexpectedly", event)
    # perform the actual unshare
    await near.unshare(task.base.sysif, UnshareFlag.FILES)
    await process.kill(Signals.SIGCONT)
    await process.waitid(W.ALL|W.EXITED, siginfo_buf)
    event = await process.read_event()
    if not event.clean():
        raise Exception("unshare function child died uncleanly", event)
    # perform a cloexec
    if not going_to_exec:
        await do_cloexec_except(task, process_resources, copy_to_new_space)

async def make_connections(access_task: Task,
                           # regrettably asymmetric...
                           # it would be nice to unify connect/accept with passing file descriptors somehow.
                           access_connection: t.Optional[t.Tuple[Path, handle.FileDescriptor]],
                           connecting_task: Task,
                           connecting_connection: t.Tuple[handle.FileDescriptor, handle.FileDescriptor],
                           parent_task: Task,
                           count: int) -> t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]]:
    # so there's 1. the access task, through which we access the syscall and data fds,
    # 2. the parent task, and
    # 3. the connection between the access and parent task, so that we can have the parent task pass down the fds,
    # while the access task uses them.
    # okay but this is a slight simplification, because there may also be,
    # 4. the connection task, which is a task that actually gets the fds and passes them down to the parent task
    access_socks: t.List[handle.FileDescriptor] = []
    connecting_socks: t.List[handle.FileDescriptor] = []
    if access_task.base.fd_table == connecting_task.base.fd_table:
        async def make_conn() -> t.Tuple[handle.FileDescriptor, handle.FileDescriptor]:
            pair = await (await access_task.base.socketpair(
                AF.UNIX, SOCK.STREAM, 0, await access_task.malloc_struct(handle.FDPair))).read()
            return (pair.first, pair.second)
    else:
        if access_connection is not None:
            access_connection_path, access_connection_socket = access_connection
        else:
            raise Exception("must pass access connection when access task and connecting task are different")
        async def make_conn() -> t.Tuple[handle.FileDescriptor, handle.FileDescriptor]:
            left_sock = await access_task.base.socket(AF.UNIX, SOCK.STREAM)
            async with access_connection_path.as_sockaddr_un() as addr:
                await left_sock.connect(await access_task.to_pointer(addr))
            right_sock = await access_connection_socket.accept(SOCK.CLOEXEC)
            return left_sock, right_sock
    for _ in range(count):
        access_sock, connecting_sock = await make_conn()
        access_socks.append(access_sock)
        connecting_socks.append(connecting_sock)
    passed_socks: t.List[handle.FileDescriptor]
    if connecting_task.base.fd_table == parent_task.base.fd_table:
        passed_socks = []
        for sock in connecting_socks:
            passed_socks.append(sock.move(parent_task.base))
    else:
        assert connecting_connection is not None
        def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.SendMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([sock for sock in connecting_socks])]))
            return sem.to_pointer(handle.SendMsghdr(None, iovec, cmsgs))
        _, [] = await connecting_connection[0].sendmsg(await connecting_task.perform_batch(sendmsg_op), SendmsgFlags.NONE)
        def recvmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.RecvMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([sock for sock in connecting_socks])]))
            return sem.to_pointer(handle.RecvMsghdr(None, iovec, cmsgs))
        _, [], hdr = await connecting_connection[1].recvmsg(await parent_task.perform_batch(recvmsg_op), RecvmsgFlags.NONE)
        cmsgs_ptr = (await hdr.read()).control
        if cmsgs_ptr is None:
            raise Exception("cmsgs field of header is, impossibly, None")
        [cmsg] = await cmsgs_ptr.read()
        if not isinstance(cmsg, handle.CmsgSCMRights):
            raise Exception("expected SCM_RIGHTS cmsg, instead got", cmsg)
        passed_socks = cmsg
        # don't need these in the connecting task anymore
        for sock in connecting_socks:
            await sock.close()
    ret = list(zip(access_socks, passed_socks))
    return ret

class RsyscallThread:
    def __init__(self,
                 stdtask: StandardTask,
                 parent_monitor: ChildProcessMonitor,
    ) -> None:
        self.stdtask = stdtask
        self.parent_monitor = parent_monitor

    async def exec(self, command: Command,
                   inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> AsyncChildProcess:
        return (await self.execve(command.executable_path, command.arguments, command.env_updates,
                                  inherited_signal_blocks=inherited_signal_blocks))

    async def execveat(self, path: handle.Path,
                       argv: t.List[bytes], envp: t.List[bytes], flags: AT) -> AsyncChildProcess:
        def op(sem: batch.BatchSemantics) -> t.Tuple[handle.WrittenPointer[handle.Path],
                                                     handle.WrittenPointer[handle.ArgList],
                                                     handle.WrittenPointer[handle.ArgList]]:
            argv_ptrs = handle.ArgList([sem.to_pointer(handle.Arg(arg)) for arg in argv])
            envp_ptrs = handle.ArgList([sem.to_pointer(handle.Arg(arg)) for arg in envp])
            return (sem.to_pointer(path),
                    sem.to_pointer(argv_ptrs),
                    sem.to_pointer(envp_ptrs))
        filename, argv_ptr, envp_ptr = await self.stdtask.task.perform_batch(op)
        child_process = await self.stdtask.task.base.execve(filename, argv_ptr, envp_ptr, flags)
        return self.parent_monitor.internal.add_task(child_process)

    async def execve(self, path: handle.Path, argv: t.Sequence[t.Union[str, bytes, os.PathLike]],
                     env_updates: t.Mapping[str, t.Union[str, bytes, os.PathLike]]={},
                     inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> AsyncChildProcess:
        """Replace the running executable in this thread with another.

        We take inherited_signal_blocks as an argument so that we can default it
        to "inheriting" an empty signal mask. Most programs expect the signal
        mask to be cleared on startup. Since we're using signalfd as our signal
        handling method, we need to block signals with the signal mask; and if
        those blocked signals were inherited across exec, other programs would
        break (SIGCHLD is the most obvious example).

        We could depend on the user clearing the signal mask before calling
        exec, similar to how we require the user to remove CLOEXEC from
        inherited fds; but that is a fairly novel requirement to most, so for
        simplicity we just default to clearing the signal mask before exec, and
        allow the user to explicitly pass down additional signal blocks.

        """
        sigmask: t.Set[signal.Signals] = set()
        for block in inherited_signal_blocks:
            sigmask = sigmask.union(block.mask)
        await self.stdtask.task.base.sigprocmask((HowSIG.SETMASK, await self.stdtask.task.to_pointer(Sigset(sigmask))))
        envp: t.Dict[bytes, bytes] = {**self.stdtask.environment}
        for key in env_updates:
            envp[os.fsencode(key)] = os.fsencode(env_updates[key])
        raw_envp: t.List[bytes] = []
        for key_bytes, value in envp.items():
            raw_envp.append(b''.join([key_bytes, b'=', value]))
        task = self.stdtask.task
        logger.info("execveat(%s, %s, %s)", path, argv, env_updates)
        return await self.execveat(path, [os.fsencode(arg) for arg in argv], raw_envp, AT.NONE)

    async def run(self, command: Command, check=True, *, task_status=trio.TASK_STATUS_IGNORED) -> ChildEvent:
        child = await command.exec(self)
        task_status.started(child)
        exit_event = await child.wait_for_exit()
        if check:
            exit_event.check()
        return exit_event

    async def close(self) -> None:
        await self.stdtask.task.close()

    async def __aenter__(self) -> StandardTask:
        return self.stdtask

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()

class Pipe(t.NamedTuple):
    rfd: MemFileDescriptor
    wfd: MemFileDescriptor

    async def aclose(self):
        await self.rfd.aclose()
        await self.wfd.aclose()

    async def __aenter__(self) -> Pipe:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

T_command = t.TypeVar('T_command', bound="Command")
class Command:
    def __init__(self,
                 executable_path: handle.Path,
                 arguments: t.List[t.Union[str, bytes, os.PathLike]],
                 env_updates: t.Mapping[str, t.Union[str, bytes, os.PathLike]]) -> None:
        self.executable_path = executable_path
        self.arguments = arguments
        self.env_updates = env_updates

    def args(self: T_command, *args: t.Union[str, bytes, os.PathLike]) -> T_command:
        return type(self)(self.executable_path,
                          [*self.arguments, *args],
                          self.env_updates)

    def env(self: T_command, env_updates: t.Mapping[str, t.Union[str, bytes, os.PathLike]]={},
            **updates: t.Union[str, bytes, os.PathLike]) -> T_command:
        return type(self)(self.executable_path,
                          self.arguments,
                          {**self.env_updates, **env_updates, **updates})

    def in_shell_form(self) -> str:
        ret = ""
        for key, value in self.env_updates.items():
            ret += os.fsdecode(key) + "=" + os.fsdecode(value)
        ret += os.fsdecode(self.executable_path)
        # skip first argument
        for arg in self.arguments[1:]:
            ret += " " + os.fsdecode(arg)
        return ret

    def __str__(self) -> str:
        ret = "Command("
        for key, value in self.env_updates.items():
            ret += f"{key}={value} "
        ret += f"{os.fsdecode(self.executable_path)},"
        for arg in self.arguments:
            ret += " " + os.fsdecode(arg)
        ret += ")"
        return ret

    # hmm we actually need an rsyscallthread to properly exec
    # would be nice to call this just "Thread".
    # we should namespace the current "Thread" properly, so we can do that...
    async def exec(self, thread: RsyscallThread) -> AsyncChildProcess:
        return (await thread.execve(self.executable_path, self.arguments, self.env_updates))


async def exec_cat(thread: RsyscallThread, cat: Command,
                   stdin: handle.FileDescriptor, stdout: handle.FileDescriptor) -> AsyncChildProcess:
    await thread.stdtask.unshare_files_and_replace({
        thread.stdtask.stdin.handle: stdin,
        thread.stdtask.stdout.handle: stdout,
    }, going_to_exec=True)
    child_task = await cat.exec(thread)
    return child_task

async def read_all(fd: MemFileDescriptor) -> bytes:
    buf = b""
    while True:
        data = await fd.read()
        if len(data) == 0:
            return buf
        buf += data

async def read_full(read: t.Callable[[int], t.Awaitable[bytes]], size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        buf += await read(size - len(buf))
    return buf
