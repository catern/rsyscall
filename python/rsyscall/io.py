from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import types
import traceback
import pathlib

import math

from rsyscall.exceptions import RsyscallException, RsyscallHangup

import rsyscall.handle as handle
import rsyscall.handle
from rsyscall.handle import T_pointer, Stack, WrittenPointer, MemoryMapping, FutexNode, Arg, ThreadProcess, Sockbuf, MemoryGateway
import rsyscall.far as far
import rsyscall.near as near
from rsyscall.struct import T_struct, T_fixed_size, Bytes, Int32, Serializer, Struct
import rsyscall.batch as batch

import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.concurrency import OneAtATime
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor

from rsyscall.sys.socket import AF, SOCK, SOL, SO, Address, Socklen, GenericSockaddr, SendmsgFlags, RecvmsgFlags
from rsyscall.fcntl import AT, O, F
from rsyscall.sys.socket import T_addr
from rsyscall.sys.mount import MS
from rsyscall.sys.un import SockaddrUn, PathTooLongError
from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.sys.epoll import EpollEvent, EpollEventList, EPOLL, EPOLL_CTL, EpollFlag
from rsyscall.sys.wait import CLD, UncleanExit, ChildEvent, W
from rsyscall.sys.memfd import MFD
from rsyscall.sys.signalfd import SFD, SignalfdSiginfo
from rsyscall.sys.inotify import InotifyFlag
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sched import UnshareFlag, CLONE
from rsyscall.signal import SigprocmaskHow, Sigaction, Sighandler, Signals, Sigset, Siginfo
from rsyscall.linux.dirent import Dirent, DirentList
from rsyscall.unistd import SEEK

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

def raise_if_error(response: int) -> None:
    if -4095 < response < 0:
        err = -response
        raise OSError(err, os.strerror(err))

def log_syscall(logger, number, arg1, arg2, arg3, arg4, arg5, arg6) -> None:
    if arg6 == 0:
        if arg5 == 0:
            if arg4 == 0:
                if arg3 == 0:
                    if arg2 == 0:
                        if arg1 == 0:
                            logger.debug("%s()", number)
                        else:
                            logger.debug("%s(%s)", number, arg1)
                    else:
                        logger.debug("%s(%s, %s)", number, arg1, arg2)
                else:
                    logger.debug("%s(%s, %s, %s)", number, arg1, arg2, arg3)
            else:
                logger.debug("%s(%s, %s, %s, %s)", number, arg1, arg2, arg3, arg4)
        else:
            logger.debug("%s(%s, %s, %s, %s, %s)", number, arg1, arg2, arg3, arg4, arg5)
    else:
        logger.debug("%s(%s, %s, %s, %s, %s, %s)", number, arg1, arg2, arg3, arg4, arg5, arg6)

class SignalMask:
    def __init__(self, mask: t.Set[Signals]) -> None:
        self.mask = mask

    def inherit(self) -> 'SignalMask':
        return SignalMask(self.mask)

    async def _sigprocmask(self, task: Task, how: SigprocmaskHow, mask: Sigset) -> None:
        if task.sigmask != self:
            raise Exception("SignalMask", self, "running for task", task,
                            "which contains a different SignalMask", task.sigmask)
        newset = await task.to_pointer(Sigset(mask))
        oldset = await task.malloc_struct(Sigset)
        await task.base.sigprocmask((how, newset), oldset)
        old_mask = await oldset.read()
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync, thought mask was",
                            self.mask, "but was actually", old_mask)

    async def block(self, task: 'Task', mask: Sigset) -> None:
        await self._sigprocmask(task, SigprocmaskHow.BLOCK, mask)
        self.mask = self.mask.union(mask)

    async def unblock(self, task: 'Task', mask: Sigset) -> None:
        await self._sigprocmask(task, SigprocmaskHow.UNBLOCK, mask)
        self.mask = self.mask - mask

    async def setmask(self, task: 'Task', mask: Sigset) -> None:
        await self._sigprocmask(task, SigprocmaskHow.SETMASK, mask)
        self.mask = mask

T = t.TypeVar('T')
class File:
    """This is the underlying file object referred to by a file descriptor.

    Often, multiple file descriptors in multiple processes can refer
    to the same file object. For example, the stdin/stdout/stderr file
    descriptors will typically all refer to the same file object
    across several processes started by the same shell.

    This is unfortunate, because there are some useful mutations (in
    particular, setting O_NONBLOCK) which we'd like to perform to
    Files, but which might break other users.

    We store whether the File is shared with others with
    "shared". If it is, we can't mutate it.

    """
    shared: bool
    def __init__(self, shared: bool=False, flags: int=None) -> None:
        self.shared = shared

T_file = t.TypeVar('T_file', bound=File)
T_file_co = t.TypeVar('T_file_co', bound=File, covariant=True)

class Task(RAM):
    def __init__(self,
                 base_: handle.Task,
                 transport: handle.MemoryTransport,
                 allocator: memory.AllocatorClient,
                 sigmask: SignalMask,
    ) -> None:
        super().__init__(base_, transport, allocator)
        self.base = base_
        self.sigmask = sigmask

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

    def _make_fd(self, num: int, file: T_file) -> MemFileDescriptor:
        return self.make_fd(near.FileDescriptor(num), file)

    def make_fd(self, fd: near.FileDescriptor, file: T_file) -> MemFileDescriptor:
        return FileDescriptor(self, self.base.make_fd_handle(fd), file)

    # TODO maybe we'll put these calls as methods on a MemoryAbstractor,
    # and they'll take an handle.FileDescriptor.
    # then we'll directly have StandardTask contain both Task and MemoryAbstractor?
    async def pipe(self, flags=O.CLOEXEC) -> Pipe:
        pipe = await (await self.base.pipe(await self.malloc_struct(handle.Pipe), O.CLOEXEC)).read()
        return Pipe(FileDescriptor(self, pipe.read, File()),
                    FileDescriptor(self, pipe.write, File()))

    async def socketpair(self, domain: AF, type: SOCK, protocol: int) -> t.Tuple[FileDescriptor, FileDescriptor]:
        pair = await (await self.base.socketpair(domain, type, protocol, await self.malloc_struct(handle.FDPair))).read()
        return (FileDescriptor(self, pair.first, File()),
                FileDescriptor(self, pair.second, File()))

    async def socket_unix(self, type: SOCK, protocol: int=0, cloexec=True) -> MemFileDescriptor:
        sockfd = await self.base.socket(AF.UNIX, type, protocol, cloexec=cloexec)
        return FileDescriptor(self, sockfd, UnixSocketFile())

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

class ReadableFile(File):
    pass

class WritableFile(File):
    pass

class SeekableFile(File):
    pass

class ReadableWritableFile(ReadableFile, WritableFile):
    pass

class SignalFile(ReadableFile):
    pass

class MemoryFile(ReadableWritableFile, SeekableFile):
    pass

class DirectoryFile(SeekableFile):
    pass

class SocketFile(t.Generic[T_addr], ReadableWritableFile):
    address_type: t.Type[T_addr]

class UnixSocketFile(SocketFile[SockaddrUn]):
    address_type = SockaddrUn

class InetSocketFile(SocketFile[SockaddrIn]):
    address_type = SockaddrIn

class InotifyFile(ReadableFile):
    pass

class MemFileDescriptor(t.Generic[T_file_co]):
    "A file descriptor, plus a task to access it from, plus the file object underlying the descriptor."
    task: Task
    file: T_file_co
    def __init__(self, task: Task, handle: handle.FileDescriptor, file: T_file_co) -> None:
        self.task = task
        self.handle = handle
        self.file = file
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
            return self.__class__(self.task, task.make_fd_handle(self.handle), self.file)
        else:
            raise Exception("file descriptor already closed")

    def move(self, task: handle.Task) -> 'MemFileDescriptor':
        if self.open:
            return self.__class__(self.task, self.handle.move(task), self.file)
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

    # These are just helper methods which forward to the method on the underlying file object.
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
        return FileDescriptor(self.task, fd, type(self.file)()), addr
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
        file: File
        if flags & O.PATH:
            file = File()
        elif flags & O.WRONLY:
            file = WritableFile()
        elif flags & O.RDWR:
            file = ReadableWritableFile()
        elif flags & O.DIRECTORY:
            file = DirectoryFile()
        else:
            # O.RDONLY is 0, so if we don't have any of the rest, then...
            file = ReadableFile()
        fd = await self.task.base.open(await self.to_pointer(), flags, mode)
        return FileDescriptor(self.task, fd, file)

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

@dataclass
class Trampoline(handle.Serializable, handle.Borrowable):
    function: handle.Pointer[handle.NativeFunction]
    args: t.List[t.Union[handle.FileDescriptor, handle.WrittenPointer[handle.Borrowable], handle.Pointer, int]]

    def __post_init__(self) -> None:
        if len(self.args) > 6:
            raise Exception("only six arguments can be passed via trampoline")

    def to_bytes(self) -> bytes:
        args: t.List[int] = []
        for arg in self.args:
            if isinstance(arg, handle.FileDescriptor):
                args.append(int(arg.near))
            elif isinstance(arg, handle.Pointer):
                args.append(int(arg.near))
            else:
                args.append(int(arg))
        arg1, arg2, arg3, arg4, arg5, arg6 = args + [0]*(6 - len(args))
        struct = ffi.new('struct rsyscall_trampoline_stack*', {
            'function': ffi.cast('void*', int(self.function.near)),
            'rdi': int(arg1),
            'rsi': int(arg2),
            'rdx': int(arg3),
            'rcx': int(arg4),
            'r8':  int(arg5),
            'r9':  int(arg6),
        })
        return bytes(ffi.buffer(struct))

    def borrow_with(self, stack: contextlib.ExitStack, task: handle.Task) -> None:
        stack.enter_context(self.function.borrow(task))
        for arg in self.args:
            if isinstance(arg, int):
                pass
            elif isinstance(arg, handle.WrittenPointer):
                arg.value.borrow_with(stack, task)
            else:
                stack.enter_context(arg.borrow(task))

    T = t.TypeVar('T', bound='Trampoline')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("not implemented")

class StaticAllocation(handle.AllocationInterface):
    def offset(self) -> int:
        return 0

    def size(self) -> int:
        raise Exception

    def split(self, size: int) -> t.Tuple[handle.AllocationInterface, handle.AllocationInterface]:
        raise Exception

    def merge(self, other: handle.AllocationInterface) -> handle.AllocationInterface:
        raise Exception("can't merge")

    def free(self) -> None:
        pass

class NullGateway(MemoryGateway):
    async def batch_read(self, ops: t.List[handle.Pointer]) -> t.List[bytes]:
        raise Exception("shouldn't try to read")
    async def batch_write(self, ops: t.List[t.Tuple[handle.Pointer, bytes]]) -> None:
        raise Exception("shouldn't try to write")

@dataclass
class ProcessResources:
    server_func: handle.Pointer[handle.NativeFunction]
    persistent_server_func: handle.Pointer[handle.NativeFunction]
    do_cloexec_func: handle.Pointer[handle.NativeFunction]
    stop_then_close_func: handle.Pointer[handle.NativeFunction]
    trampoline_func: handle.Pointer[handle.NativeFunction]
    futex_helper_func: handle.Pointer[handle.NativeFunction]

    @staticmethod
    def make_from_symbols(task: handle.Task, symbols: t.Any) -> ProcessResources:
        def to_handle(cffi_ptr) -> handle.Pointer[handle.NativeFunction]:
            pointer_int = int(ffi.cast('ssize_t', cffi_ptr))
            # TODO we're just making up a memory mapping that this pointer is inside;
            # we should figure out the actual mapping, and the size for that matter.
            mapping = MemoryMapping(task, near.MemoryMapping(pointer_int, 0, 1), near.File())
            return handle.Pointer(mapping, NullGateway(), handle.NativeFunctionSerializer(), StaticAllocation())
        return ProcessResources(
            server_func=to_handle(symbols.rsyscall_server),
            persistent_server_func=to_handle(symbols.rsyscall_persistent_server),
            do_cloexec_func=to_handle(symbols.rsyscall_do_cloexec),
            stop_then_close_func=to_handle(symbols.rsyscall_stop_then_close),
            trampoline_func=to_handle(symbols.rsyscall_trampoline),
            futex_helper_func=to_handle(symbols.rsyscall_futex_helper),
        )

    def build_trampoline_stack(self, function: handle.Pointer[handle.NativeFunction],
                               arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> bytes:
        # TODO clean this up with dicts or tuples or something
        stack_struct = ffi.new('struct rsyscall_trampoline_stack*')
        stack_struct.rdi = int(arg1)
        stack_struct.rsi = int(arg2)
        stack_struct.rdx = int(arg3)
        stack_struct.rcx = int(arg4)
        stack_struct.r8  = int(arg5)
        stack_struct.r9  = int(arg6)
        stack_struct.function = ffi.cast('void*', int(function.near))
        logger.info("trampoline_func %s", self.trampoline_func.near)
        packed_trampoline_addr = struct.pack('Q', int(self.trampoline_func.near))
        stack = packed_trampoline_addr + bytes(ffi.buffer(stack_struct))
        return stack

    def make_trampoline_stack(self, trampoline: Trampoline) -> handle.Stack[Trampoline]:
        # ugh okaaaaaaaaaaaaay
        # need to figure out how to handle these function pointers. hMmMmM
        return handle.Stack(self.trampoline_func, trampoline, trampoline.get_serializer(None))

trampoline_stack_size = ffi.sizeof('struct rsyscall_trampoline_stack') + 8

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
                 access_connection: t.Optional[t.Tuple[Path, MemFileDescriptor]],
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
        task = await spawn_rsyscall_thread(
            access_sock, remote_sock,
            self.task, self.child_monitor, self.process,
            newuser=newuser, newpid=newpid, fs=fs, sighand=sighand,
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
            signal_block = SignalBlock(task, {signal.SIGCHLD})
            child_monitor = await ChildProcessMonitor.make(task, epoller, signal_block=signal_block, is_reaper=newpid)
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

class SignalBlock:
    """This represents some signals being blocked from normal handling

    We need this around to use alternative signal handling mechanisms
    such as signalfd.

    """
    task: Task
    mask: t.Set[signal.Signals]
    @staticmethod
    async def make(task: Task, mask: t.Set[signal.Signals]) -> 'SignalBlock':
        if len(mask.intersection(task.sigmask.mask)) != 0:
            raise Exception("can't allocate a SignalBlock for a signal that was already blocked",
                            mask, task.sigmask.mask)
        await task.sigmask.block(task, Sigset(mask))
        return SignalBlock(task, mask)

    def __init__(self, task: Task, mask: t.Set[signal.Signals]) -> None:
        self.task = task
        self.mask = mask

    async def close(self) -> None:
        await self.task.sigmask.unblock(self.task, Sigset(self.mask))

    async def __aenter__(self) -> 'SignalBlock':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class SignalQueue:
    def __init__(self, signal_block: SignalBlock, sigfd: AsyncFileDescriptor) -> None:
        self.signal_block = signal_block
        self.sigfd = sigfd

    @classmethod
    async def make(cls, task: Task, epoller: EpollCenter, mask: t.Set[signal.Signals],
                   *, signal_block: SignalBlock=None,
    ) -> SignalQueue:
        if signal_block is None:
            signal_block = await SignalBlock.make(task, mask)
        else:
            if signal_block.mask != mask:
                raise Exception("passed-in SignalBlock", signal_block, "has mask", signal_block.mask,
                                "which does not match the mask for the SignalQueue we're making", mask)
        sigfd = await task.base.signalfd(await task.to_pointer(Sigset(mask)), SFD.NONBLOCK|SFD.CLOEXEC)
        async_sigfd = await AsyncFileDescriptor.make_handle(epoller, task, sigfd, is_nonblock=True)
        return cls(signal_block, async_sigfd)

    async def read(self, buf: handle.Pointer) -> handle.Pointer:
        validp, _ = await self.sigfd.read_handle(buf)
        return validp

    async def close(self) -> None:
        await self.signal_block.close()
        await self.sigfd.aclose()

    async def __aenter__(self) -> 'SignalQueue':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class ChildProcess:
    def __init__(self, process: handle.ChildProcess,
                 monitor: ChildProcessMonitorInternal) -> None:
        self.process = process
        self.monitor = monitor
        self.task = self.monitor.waiting_task

    async def waitid_nohang(self) -> t.Optional[ChildEvent]:
        if self.process.unread_siginfo is None:
            await self.process.waitid(W.EXITED|W.STOPPED|W.CONTINUED|W.ALL|W.NOHANG,
                                      await self.task.malloc_struct(Siginfo))
        return await self.process.read_siginfo()

    async def wait(self) -> t.List[ChildEvent]:
        with self.monitor.sigchld_waiter() as waiter:
            while True:
                event = await self.waitid_nohang()
                if event is None:
                    await waiter.wait_for_sigchld()
                else:
                    return [event]

    async def wait_for_exit(self) -> ChildEvent:
        if self.process.death_event:
            return self.process.death_event
        while True:
            for event in (await self.wait()):
                if event.died():
                    return event

    async def check(self) -> ChildEvent:
        death = await self.wait_for_exit()
        death.check()
        return death

    async def wait_for_stop_or_exit(self) -> ChildEvent:
        while True:
            for event in (await self.wait()):
                if event.died():
                    return event
                elif event.code == CLD.STOPPED:
                    return event

    async def send_signal(self, sig: signal.Signals) -> None:
        await self.process.kill(sig)

    async def kill(self) -> None:
        await self.process.kill(Signals.SIGKILL)

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        if self.process.death_event:
            pass
        else:
            await self.kill()
            await self.wait_for_exit()

@dataclass(eq=False)
class SigchldWaiter:
    monitor: ChildProcessMonitorInternal
    got_sigchld: bool = False

    async def wait_for_sigchld(self) -> None:
        if not self.got_sigchld:
            await self.monitor.do_wait()

class ChildProcessMonitorInternal:
    def __init__(self, waiting_task: Task, signal_queue: SignalQueue, is_reaper: bool) -> None:
        self.waiting_task = waiting_task
        self.signal_queue = signal_queue
        self.is_reaper = is_reaper
        if self.signal_queue.signal_block.mask != set([signal.SIGCHLD]):
            raise Exception("ChildProcessMonitor should get a SignalQueue only for SIGCHLD")
        self.running_wait = OneAtATime()
        self.waiters: t.List[SigchldWaiter] = []

    def add_task(self, process: handle.ChildProcess) -> ChildProcess:
        proc = ChildProcess(process, self)
        # self.processes.append(proc)
        return proc

    @contextlib.contextmanager
    def sigchld_waiter(self) -> t.Iterator[SigchldWaiter]:
        waiter = SigchldWaiter(self)
        self.waiters.append(waiter)
        yield waiter
        self.waiters.remove(waiter)

    async def clone(self,
                    clone_task: handle.Task,
                    flags: CLONE,
                    child_stack: t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[handle.Pointer]=None) -> ChildProcess:
        process = await clone_task.clone(flags|Signals.SIGCHLD, child_stack, None, ctid, None)
        return self.add_task(process)

    async def do_wait(self) -> None:
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                buf = await self.waiting_task.malloc_struct(SignalfdSiginfo)
                # we don't care what information we get from the signal, we just want to
                # sleep until a SIGCHLD happens
                await self.signal_queue.read(buf)
                for waiter in self.waiters:
                    waiter.got_sigchld = True

    async def close(self) -> None:
        await self.signal_queue.close()

@dataclass
class ChildProcessMonitor:
    internal: ChildProcessMonitorInternal
    cloning_task: handle.Task
    use_clone_parent: bool
    is_reaper: bool

    @staticmethod
    async def make(task: Task, epoller: EpollCenter,
                   *, signal_block: SignalBlock=None,
                   is_reaper: bool=False,
    ) -> ChildProcessMonitor:
        signal_queue = await SignalQueue.make(task, epoller, {signal.SIGCHLD}, signal_block=signal_block)
        monitor = ChildProcessMonitorInternal(task, signal_queue, is_reaper=is_reaper)
        return ChildProcessMonitor(monitor, task.base, use_clone_parent=False, is_reaper=is_reaper)

    def inherit_to_child(self, child_task: handle.Task) -> ChildProcessMonitor:
        if self.is_reaper:
            # TODO we should actually look at something on the Task, I suppose, to determine if we're a reaper
            raise Exception("we're a ChildProcessMonitor for a reaper task, "
                            "we can't be inherited because we can't use CLONE_PARENT")
        if child_task.parent_task is not self.internal.waiting_task.base:
            raise Exception("task", child_task, "with parent_task", child_task.parent_task,
                            "is not our child; we're", self.internal.waiting_task.base)
        # we now know that the cloning task is in a process which is a child process of the waiting task.  so
        # we know that if use CLONE_PARENT while cloning in the cloning task, the resulting tasks will be
        # children of the waiting task, so we can use the waiting task to wait on them.
        return ChildProcessMonitor(self.internal, child_task, use_clone_parent=True, is_reaper=self.is_reaper)

    def inherit_to_thread(self, cloning_task: handle.Task) -> ChildProcessMonitor:
        if self.internal.waiting_task.base.process is not cloning_task.process:
            raise Exception("waiting task process", self.internal.waiting_task.base.process,
                            "is not the same as cloning task process", cloning_task.process)
        # we know that the cloning task is in the same process as the waiting task. so any children the
        # cloning task starts will also be waitable-on by the waiting task.
        return ChildProcessMonitor(self.internal, cloning_task, use_clone_parent=False, is_reaper=self.is_reaper)

    async def clone(self, flags: CLONE,
                    child_stack: t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[handle.Pointer[FutexNode]]=None) -> ChildProcess:
        if self.use_clone_parent:
            flags |= CLONE.PARENT
        return (await self.internal.clone(self.cloning_task, flags, child_stack, ctid=ctid))

async def launch_futex_monitor(task: Task,
                               process_resources: ProcessResources, monitor: ChildProcessMonitor,
                               futex_pointer: WrittenPointer[FutexNode]) -> ChildProcess:
    async def op(sem: batch.BatchSemantics) -> t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]]:
        stack_value = process_resources.make_trampoline_stack(Trampoline(
            process_resources.futex_helper_func, [
                int(futex_pointer.near + ffi.offsetof('struct futex_node', 'futex')),
                futex_pointer.value.futex]))
        stack_buf = sem.malloc_type(handle.Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        return stack
    stack = await task.perform_async_batch(op)
    futex_task = await monitor.clone(CLONE.VM|CLONE.FILES, stack)
    # wait for futex helper to SIGSTOP itself,
    # which indicates the trampoline is done and we can deallocate the stack.
    event = await futex_task.wait_for_stop_or_exit()
    if event.died():
        raise Exception("thread internal futex-waiting task died unexpectedly", event)
    # resume the futex_task so it can start waiting on the futex
    await futex_task.send_signal(signal.SIGCONT)
    # the stack will be freed as it is no longer needed, but the futex pointer will live on
    return futex_task

@dataclass
class RsyscallSyscall(Struct):
    number: int
    arg1: int
    arg2: int
    arg3: int
    arg4: int
    arg5: int
    arg6: int

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct rsyscall_syscall const*', {
            "sys": self.number,
            "args": (self.arg1, self.arg2, self.arg3, self.arg4, self.arg5, self.arg6),
        })))

    T = t.TypeVar('T', bound='RsyscallSyscall')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct rsyscall_syscall*', ffi.from_buffer(data))
        return cls(struct.sys,
                   struct.args[0], struct.args[1], struct.args[2],
                   struct.args[3], struct.args[4], struct.args[5])

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct rsyscall_syscall')

@dataclass
class RsyscallResponse(Struct):
    value: int

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('long const*', self.value)))

    T = t.TypeVar('T', bound='RsyscallResponse')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('long*', ffi.from_buffer(data))
        return cls(struct[0])

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('long')

class ReadBuffer:
    def __init__(self) -> None:
        self.buf = b""

    def feed_bytes(self, data: bytes) -> None:
        self.buf += data

    def read_struct(self, cls: t.Type[T_struct]) -> t.Optional[T_struct]:
        length = cls.sizeof()
        if length <= len(self.buf):
            section = self.buf[:length]
            self.buf = self.buf[length:]
            return cls.from_bytes(section)
        else:
            return None

class RsyscallConnection:
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 tofd: AsyncFileDescriptor,
                 fromfd: AsyncFileDescriptor,
    ) -> None:
        self.tofd = tofd
        self.fromfd = fromfd
        self.buffer = ReadBuffer()
        self.valid: t.Optional[handle.Pointer[Bytes]] = None

    async def close(self) -> None:
        await self.tofd.aclose()
        await self.fromfd.aclose()

    async def write_request(self, number: int,
                            arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> None:
        request = RsyscallSyscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        ptr = await self.tofd.ram.to_pointer(request)
        try:
            await self.tofd.write_handle(ptr)
        except OSError as e:
            # we raise a different exception so that users can distinguish syscall errors from
            # transport errors
            raise RsyscallException() from e

    def poll_response(self) -> t.Optional[int]:
        val = self.buffer.read_struct(RsyscallResponse)
        if val:
            return val.value
        else:
            return None

    async def read_response(self) -> int:
        val = self.buffer.read_struct(RsyscallResponse)
        if val:
            return val.value
        buf = await self.fromfd.ram.malloc_type(Bytes, 256)
        while val is None:
            if self.valid is None:
                valid, rest = await self.fromfd.read_handle(buf)
                if valid.bytesize() == 0:
                    raise RsyscallHangup()
                self.valid = valid
            data = await self.valid.read()
            self.valid = None
            self.buffer.feed_bytes(data)
            buf = valid.merge(rest)
            val = self.buffer.read_struct(RsyscallResponse)
        return val.value

class ChildExit(RsyscallHangup):
    pass

class MMRelease(RsyscallHangup):
    pass

@dataclass
class SyscallResponse(near.SyscallResponse):
    process_one_response: t.Any
    result: t.Optional[t.Union[Exception, int]] = None

    async def receive(self) -> int:
        while self.result is None:
            await self.process_one_response()
        else:
            if isinstance(self.result, int):
                return self.result
            else:
                raise self.result

    def set_exception(self, exn: Exception) -> None:
        if self.result is not None:
            raise Exception("trying to set result on SyscallResponse twice")
        self.result = exn

    def set_result(self, result: int) -> None:
        if self.result is not None:
            raise Exception("trying to set result on SyscallResponse twice")
        self.result = result

class ChildConnection(near.SyscallInterface):
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 rsyscall_connection: RsyscallConnection,
                 server_task: ChildProcess,
                 futex_task: t.Optional[ChildProcess],
    ) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.server_task = server_task
        self.futex_task = futex_task
        self.identifier_process = self.server_task.process.near
        self.logger = logging.getLogger(f"rsyscall.ChildConnection.{int(self.server_task.process.near)}")
        self.infd: handle.FileDescriptor
        self.outfd: handle.FileDescriptor
        self.activity_fd: near.FileDescriptor
        self.request_lock = trio.Lock()
        self.pending_responses: t.List[SyscallResponse] = []
        self.running_read = OneAtATime()

    def store_remote_side_handles(self, infd: handle.FileDescriptor, outfd: handle.FileDescriptor) -> None:
        # these are needed so that we don't close them with garbage collection
        self.infd = infd
        self.outfd = outfd
        # this is part of the SyscallInterface
        self.activity_fd = infd.near

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def _read_syscall_response(self) -> int:
        # we poll first so that we don't unnecessarily issue waitids if we've
        # already got a response in our buffer
        response: t.Optional[int] = self.rsyscall_connection.poll_response()
        if response is not None:
            raise_if_error(response)
            return response
        try:
            async with trio.open_nursery() as nursery:
                async def read_response() -> None:
                    nonlocal response
                    response = await self.rsyscall_connection.read_response()
                    self.logger.info("read syscall response")
                    nursery.cancel_scope.cancel()
                async def server_exit() -> None:
                    # meaning the server exited
                    try:
                        self.logger.info("enter server exit")
                        await self.server_task.wait_for_exit()
                    except:
                        self.logger.info("out of server exit")
                        raise
                    raise ChildExit()
                async def futex_exit() -> None:
                    if self.futex_task is not None:
                        # meaning the server called exec or exited; we don't
                        # wait to see which one.
                        try:
                            self.logger.info("enter futex exit")
                            await self.futex_task.wait_for_exit()
                        except:
                            self.logger.info("out of futex exit")
                            raise
                        raise MMRelease()
                nursery.start_soon(read_response)
                nursery.start_soon(server_exit)
                nursery.start_soon(futex_exit)
        except:
            # if response is not None, we shouldn't let this exception through;
            # instead we should process this syscall response, and let the next syscall fail
            if response is None:
                raise
        else:
            self.logger.info("returning or raising syscall response from nursery %s", response)
        if response is None:
            raise Exception("somehow made it out of the nursery without either throwing or getting a response")
        raise_if_error(response)
        return response

    async def _process_response_for(self, response: SyscallResponse) -> None:
        try:
            ret = await self._read_syscall_response()
            self.logger.info("returned syscall response %s", ret)
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
        async with self.running_read.needs_run() as needs_run:
            if needs_run:
                await self._process_one_response_direct()

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
    await near.unshare(task.base.sysif, near.UnshareFlag.FILES)
    await process.kill(Signals.SIGCONT)
    await process.waitid(W.ALL|W.EXITED, siginfo_buf)
    event = await process.read_event()
    if not event.clean():
        raise Exception("unshare function child died uncleanly", event)
    # perform a cloexec
    if not going_to_exec:
        await do_cloexec_except(task, process_resources, copy_to_new_space)

class EOFException(Exception):
    pass

class AsyncReadBuffer:
    def __init__(self, fd: AsyncFileDescriptor) -> None:
        self.fd = fd
        self.buf = b""

    async def _read(self) -> t.Optional[bytes]:
        data = await self.fd.read()
        if len(data) == 0:
            if len(self.buf) != 0:
                raise EOFException("got EOF while we still hold unhandled buffered data")
            else:
                return None
        else:
            return data

    async def read_length(self, length: int) -> t.Optional[bytes]:
        while len(self.buf) < length:
            data = await self._read()
            if data is None:
                return None
            self.buf += data
        section = self.buf[:length]
        self.buf = self.buf[length:]
        return section

    async def read_cffi(self, name: str) -> t.Any:
        size = ffi.sizeof(name)
        data = await self.read_length(size)
        if data is None:
            raise EOFException("got EOF while expecting to read a", name)
        nameptr = name + '*'
        dest = ffi.new(nameptr)
        # ffi.cast drops the reference to the backing buffer, so we have to copy it
        src = ffi.cast(nameptr, ffi.from_buffer(data))
        ffi.memmove(dest, src, size)
        return dest[0]

    async def read_length_prefixed_string(self) -> bytes:
        elem_size = await self.read_cffi('size_t')
        elem = await self.read_length(elem_size)
        if elem is None:
            raise EOFException("got EOF while expecting to read environment element of length", elem_size)
        return elem

    async def read_length_prefixed_array(self, length: int) -> t.List[bytes]:
        ret: t.List[bytes] = []
        for _ in range(length):
            ret.append(await self.read_length_prefixed_string())
        return ret

    async def read_envp(self, length: int) -> t.Dict[bytes, bytes]:
        raw = await self.read_length_prefixed_array(length)
        environ: t.Dict[bytes, bytes] = {}
        for elem in raw:
            # if someone passes us a malformed environment element without =,
            # we'll just break, whatever
            key, val = elem.split(b"=", 1)
            environ[key] = val
        return environ

    async def read_until_delimiter(self, delim: bytes) -> t.Optional[bytes]:
        while True:
            try:
                i = self.buf.index(delim)
            except ValueError:
                pass
            else:
                section = self.buf[:i]
                # skip the delimiter
                self.buf = self.buf[i+1:]
                return section
            # buf contains no copies of "delim", gotta read some more data
            data = await self._read()
            if data is None:
                return None
            self.buf += data

    async def read_line(self) -> t.Optional[bytes]:
        return (await self.read_until_delimiter(b"\n"))

    async def read_keyval(self) -> t.Optional[t.Tuple[bytes, bytes]]:
        keyval = await self.read_line()
        if keyval is None:
            return None
        key, val = keyval.split(b"=", 1)
        return key, val

    async def read_known_keyval(self, expected_key: bytes) -> bytes:
        keyval = await self.read_keyval()
        if keyval is None:
            raise EOFException("expected key value pair with key", expected_key, "but got EOF instead")
        key, val = keyval
        if key != expected_key:
            raise EOFException("expected key", expected_key, "but got", key)
        return val

    async def read_known_int(self, expected_key: bytes) -> int:
        return int(await self.read_known_keyval(expected_key))

    async def read_known_fd(self, expected_key: bytes) -> near.FileDescriptor:
        return near.FileDescriptor(await self.read_known_int(expected_key))

    async def read_netstring(self) -> t.Optional[bytes]:
        length_bytes = await self.read_until_delimiter(b':')
        if length_bytes is None:
            return None
        length = int(length_bytes)
        data = await self.read_length(length)
        if data is None:
            raise EOFException("hangup before netstring data")
        comma = await self.read_length(1)        
        if comma is None:
            raise EOFException("hangup before comma at end of netstring")
        if comma != b",":
            raise Exception("bad netstring delimiter", comma)
        return data

async def make_connections(access_task: Task,
                           # regrettably asymmetric...
                           # it would be nice to unify connect/accept with passing file descriptors somehow.
                           access_connection: t.Optional[t.Tuple[Path, MemFileDescriptor]],
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
            right_sock = await access_connection_socket.handle.accept(SOCK.CLOEXEC)
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

async def spawn_rsyscall_thread(
        access_sock: AsyncFileDescriptor,
        remote_sock: handle.FileDescriptor,
        parent_task: Task,
        monitor: ChildProcessMonitor,
        process_resources: ProcessResources,
        newuser: bool, newpid: bool, fs: bool, sighand: bool,
) -> Task:
    flags = CLONE.VM|CLONE.FILES|CLONE.IO|CLONE.SYSVSEM|signal.SIGCHLD
    # TODO correctly track the namespaces we're in for all these things
    if newuser:
        flags |= CLONE.NEWUSER
    if newpid:
        flags |= CLONE.NEWPID
    if fs:
        flags |= CLONE.FS
    if sighand:
        flags |= CLONE.SIGHAND
    # TODO it is unclear why we sometimes need to make a new mapping here, instead of allocating with our normal
    # allocator; all our memory is already MAP.SHARED, I think.
    # We should resolve this so we can use the stock allocator.
    arena = memory.Arena(await parent_task.base.mmap(4096*2, PROT.READ|PROT.WRITE, MAP.SHARED))
    async def op(sem: batch.BatchSemantics) -> t.Tuple[t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]],
                                                       WrittenPointer[FutexNode]]:
        stack_value = process_resources.make_trampoline_stack(Trampoline(
            process_resources.server_func, [remote_sock, remote_sock]))
        stack_buf = sem.malloc_type(handle.Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        futex_pointer = sem.to_pointer(handle.FutexNode(None, Int32(0)))
        return stack, futex_pointer
    stack, futex_pointer = await batch.perform_async_batch(parent_task.base, parent_task.transport, arena, op)
    futex_process = await launch_futex_monitor(parent_task, process_resources, monitor, futex_pointer)
    child_process = await monitor.clone(flags|CLONE.CHILD_CLEARTID, stack, ctid=futex_pointer)

    syscall = ChildConnection(RsyscallConnection(access_sock, access_sock), child_process, futex_process)
    if fs:
        fs_information = parent_task.base.fs
    else:
        fs_information = far.FSInformation(child_process.process.near.id)
    if newpid:
        pidns = far.PidNamespace(child_process.process.near.id)
    else:
        pidns = parent_task.base.pidns
    netns = parent_task.base.netns
    real_parent_task = parent_task.base.parent_task if monitor.use_clone_parent else parent_task.base
    new_base_task = handle.Task(syscall, child_process.process, real_parent_task,
                              parent_task.base.fd_table, parent_task.base.address_space, fs_information, pidns, netns)
    remote_sock_handle = new_base_task.make_fd_handle(remote_sock)
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    new_task = Task(new_base_task,
                    # We don't inherit the transport because it leads to a deadlock:
                    # If when a child task calls transport.read, it performs a syscall in the child task,
                    # then the parent task will need to call waitid to monitor the child task during the syscall,
                    # which will in turn need to also call transport.read.
                    # But the child is already using the transport and holding the lock,
                    # so the parent will block forever on taking the lock,
                    # and child's read syscall will never complete.
                    parent_task.transport,
                    parent_task.allocator.inherit(new_base_task),
                    parent_task.sigmask.inherit(),
    )
    return new_task

class RsyscallThread:
    def __init__(self,
                 stdtask: StandardTask,
                 parent_monitor: ChildProcessMonitor,
    ) -> None:
        self.stdtask = stdtask
        self.parent_monitor = parent_monitor

    async def exec(self, command: Command,
                   inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> ChildProcess:
        return (await self.execve(command.executable_path, command.arguments, command.env_updates,
                                  inherited_signal_blocks=inherited_signal_blocks))

    async def execveat(self, path: handle.Path,
                       argv: t.List[bytes], envp: t.List[bytes], flags: AT) -> ChildProcess:
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
    ) -> ChildProcess:
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
        await self.stdtask.task.sigmask.setmask(self.stdtask.task, Sigset(sigmask))
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
    async def exec(self, thread: RsyscallThread) -> ChildProcess:
        return (await thread.execve(self.executable_path, self.arguments, self.env_updates))


async def exec_cat(thread: RsyscallThread, cat: Command,
                   stdin: handle.FileDescriptor, stdout: handle.FileDescriptor) -> ChildProcess:
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
