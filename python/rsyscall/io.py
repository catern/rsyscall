from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import traceback

from rsyscall.epoll import EpollEvent, EpollEventMask
import math
import rsyscall.epoll
import importlib.resources
ssh_bootstrap_script_contents = importlib.resources.read_text('rsyscall', 'ssh_bootstrap.sh')

from rsyscall.base import Pointer, RsyscallException, RsyscallHangup
from rsyscall.base import to_local_pointer
from rsyscall.base import SyscallInterface
from rsyscall.base import T_addr, UnixAddress, PathTooLongError, InetAddress
from rsyscall.base import IdType, EpollCtlOp, ChildCode, UncleanExit, ChildEvent
import rsyscall.base as base
from rsyscall.raw_syscalls import UnshareFlag, NsType, SigprocmaskHow
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory_abstracted_syscalls as memsys
import rsyscall.memory as memory
import rsyscall.handle as handle
import rsyscall.far as far
import rsyscall.near as near

from rsyscall.stat import Dirent, DType
import rsyscall.stat
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
from dataclasses import dataclass
import logging
import fcntl
import errno
import enum
import contextlib
logger = logging.getLogger(__name__)

async def direct_syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
    "Make a syscall directly in the current thread."
    args = (ffi.cast('long', arg1), ffi.cast('long', arg2), ffi.cast('long', arg3),
            ffi.cast('long', arg4), ffi.cast('long', arg5), ffi.cast('long', arg6),
            number)
    ret = lib.rsyscall_raw_syscall(*args)
    return ret

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

class LocalSyscall(base.SyscallInterface):
    activity_fd = None
    identifier_process = near.Process(os.getpid())
    logger = logging.getLogger("rsyscall.LocalSyscall")
    async def close_interface(self) -> None:
        pass

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> near.SyscallResponse:
        raise Exception("not supported for local syscaller")

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            result = await self._syscall(
                number,
                arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

    async def _syscall(self, number: int, arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> int:
        ret = await direct_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        raise_if_error(ret)
        return ret

class FunctionPointer:
    "A function pointer."
    def __init__(self, pointer: far.Pointer) -> None:
        self.pointer = pointer

class SignalMask:
    def __init__(self, mask: t.Set[signal.Signals]) -> None:
        self.mask = mask

    def inherit(self) -> 'SignalMask':
        return SignalMask(self.mask)

    def _validate(self, task: 'Task') -> SyscallInterface:
        if task.sigmask != self:
            raise Exception
        return task.syscall

    async def block(self, task: 'Task', mask: t.Set[signal.Signals]) -> None:
        syscall = self._validate(task)
        old_mask = await memsys.rt_sigprocmask(syscall, task.transport, task.allocator, SigprocmaskHow.BLOCK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync, thought mask was",
                            self.mask, "but was actually", old_mask)
        self.mask = self.mask.union(mask)

    async def unblock(self, task: 'Task', mask: t.Set[signal.Signals]) -> None:
        syscall = self._validate(task)
        old_mask = await memsys.rt_sigprocmask(syscall, task.transport, task.allocator, SigprocmaskHow.UNBLOCK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync, thought mask was",
                            self.mask, "but was actually", old_mask)
        self.mask = self.mask - mask

    async def setmask(self, task: 'Task', mask: t.Set[signal.Signals]) -> None:
        syscall = self._validate(task)
        old_mask = await memsys.rt_sigprocmask(syscall, task.transport, task.allocator, SigprocmaskHow.SETMASK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync, thought mask was",
                            self.mask, "but was actually", old_mask)
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

    async def set_nonblock(self, fd: FileDescriptor[File]) -> None:
        if self.shared:
            raise Exception("file object is shared and can't be mutated")
        if fd.file != self:
            raise Exception("can't set a file to nonblocking through a file descriptor that doesn't point to it")
        await raw_syscall.fcntl(fd.task.syscall, fd.pure, fcntl.F_SETFL, os.O_NONBLOCK)

    async def lseek(self, fd: 'FileDescriptor[File]', offset: int, whence: int) -> int:
        return (await raw_syscall.lseek(fd.task.syscall, fd.pure, offset, whence))

T_file = t.TypeVar('T_file', bound=File)
T_file_co = t.TypeVar('T_file_co', bound=File, covariant=True)

class Task:
    def __init__(self,
                 base_: base.Task,
                 transport: base.MemoryTransport,
                 allocator: memory.AllocatorClient,
                 sigmask: SignalMask,
                 process_namespace: far.ProcessNamespace,
    ) -> None:
        self.base = base_
        self.transport = transport
        # Being able to allocate memory is like having a stack.
        # we really need to be able to allocate memory to get anything done - namely, to call syscalls.
        self.allocator = allocator
        self.sigmask = sigmask
        self.process_namespace = process_namespace

    @property
    def syscall(self) -> base.SyscallInterface:
        return self.base.sysif

    @property
    def address_space(self) -> base.AddressSpace:
        return self.base.address_space

    @property
    def fd_table(self) -> base.FDTable:
        return self.base.fd_table

    def root(self) -> Path:
        return Path.from_bytes(self, b"/")

    def cwd(self) -> Path:
        return Path.from_bytes(self, b".")

    async def close(self):
        await self.syscall.close_interface()

    async def exit(self, status: int) -> None:
        await raw_syscall.exit(self.syscall, status)
        await self.close()

    async def execveat(self, path: Path,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> None:
        await memsys.execveat(self.syscall, self.transport, self.allocator, path.pure, argv, envp, flags)
        await self.close()

    async def chdir(self, path: 'Path') -> None:
        async with memsys.localize_path(self.transport, self.allocator, path.pure) as (dirfd, pathname):
            if dirfd is not None:
                await self.base.fs.fchdir(self.base, dirfd)
            await self.base.fs.chdir(self.base, pathname)

    async def unshare_fs(self) -> None:
        # we want this to return something that we can use to chdir
        raise NotImplementedError

    def _make_fd(self, num: int, file: T_file) -> FileDescriptor[T_file]:
        return self.make_fd(near.FileDescriptor(num), file)

    def make_fd(self, fd: near.FileDescriptor, file: T_file) -> FileDescriptor[T_file]:
        return FileDescriptor(self, self.base.make_fd_handle(fd), file)

    async def open(self, path: handle.Path, flags: int, mode=0o644) -> handle.FileDescriptor:
        """Open a path

        Note that this can block forever if we're opening a FIFO

        """
        fd = await memsys.openat(self.syscall, self.transport, self.allocator,
                                 path.far, flags, mode)
        return self.base.make_fd_handle(fd)

    async def read(self, fd: far.FileDescriptor, count: int=4096) -> bytes:
        return (await memsys.read(self.base, self.transport, self.allocator, fd, count))

    # TODO maybe we'll put these calls as methods on a MemoryAbstractor,
    # and they'll take an handle.FileDescriptor.
    # then we'll directly have StandardTask contain both Task and MemoryAbstractor?
    async def getdents(self, fd: far.FileDescriptor, count: int=4096) -> t.List[Dirent]:
        data = await memsys.getdents64(self.base, self.transport, self.allocator, fd, count)
        return rsyscall.stat.getdents64_parse(data)

    async def pipe(self, flags=os.O_CLOEXEC) -> Pipe:
        r, w = await memsys.pipe(self.syscall, self.transport, self.allocator, flags)
        return Pipe(self._make_fd(r, ReadableFile(shared=False)),
                    self._make_fd(w, WritableFile(shared=False)))

    async def socketpair(self, domain: int, type: int, protocol: int
    ) -> t.Tuple[FileDescriptor[ReadableWritableFile], FileDescriptor[ReadableWritableFile]]:
        l, r = await memsys.socketpair(self.syscall, self.transport, self.allocator,
                                       domain, type|lib.SOCK_CLOEXEC, protocol)
        return (self._make_fd(l, ReadableWritableFile(shared=False)),
                self._make_fd(r, ReadableWritableFile(shared=False)))

    async def epoll_create(self, flags=lib.EPOLL_CLOEXEC) -> FileDescriptor[EpollFile]:
        epfd = await raw_syscall.epoll_create(self.syscall, flags)
        return self._make_fd(epfd, EpollFile())

    async def socket_unix(self, type: socket.SocketKind, protocol: int=0) -> FileDescriptor[UnixSocketFile]:
        sockfd = await raw_syscall.socket(self.syscall, lib.AF_UNIX, type, protocol)
        return self._make_fd(sockfd, UnixSocketFile())

    async def socket_inet(self, type: socket.SocketKind, protocol: int=0) -> FileDescriptor[InetSocketFile]:
        sockfd = await raw_syscall.socket(self.syscall, lib.AF_INET, type, protocol)
        return self._make_fd(sockfd, InetSocketFile())

    async def signalfd_create(self, mask: t.Set[signal.Signals], flags: int=0) -> FileDescriptor[SignalFile]:
        sigfd = await memsys.signalfd(self.syscall, self.transport, self.allocator, mask, os.O_CLOEXEC|flags)
        return self._make_fd(sigfd, SignalFile(mask))

    async def mmap(self, length: int, prot: memory.ProtFlag, flags: memory.MapFlag) -> memory.AnonymousMapping:
        # currently doesn't support specifying an address, nor specifying a file descriptor
        return (await memory.AnonymousMapping.make(
            self.syscall, self.base.address_space, length, prot, flags))

    async def make_epoll_center(self) -> EpollCenter:
        epfd = await self.epoll_create()
        # TODO handle deallocating the epoll fd if later steps fail
        if self.syscall.activity_fd is not None:
            epoll_waiter = EpollWaiter(epfd, None)
            epoll_center = EpollCenter(epoll_waiter, epfd.handle, self.transport, self.allocator)
            other_activity_fd = self._make_fd(self.syscall.activity_fd.number, File())
            # TODO we need to save this somewhere so it can be collected
            epolled_other_activity_fd = await epoll_center.register(other_activity_fd.handle,
                                                                    events=EpollEventMask.make(in_=True))
        else:
            # TODO this is a pretty low-level detail, not sure where is the right place to do this
            async def wait_readable():
                logger.debug("wait_readable(%s)", epfd.handle.near.number)
                await trio.hazmat.wait_readable(epfd.handle.near.number)
            epoll_waiter = EpollWaiter(epfd, wait_readable)
            epoll_center = EpollCenter(epoll_waiter, epfd.handle, self.transport, self.allocator)
        return epoll_center
        

class ReadableFile(File):
    async def read(self, fd: 'FileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        return (await fd.task.read(fd.handle.far, count))

class WritableFile(File):
    async def write(self, fd: 'FileDescriptor[WritableFile]', buf: bytes) -> int:
        return (await memsys.write(fd.task.syscall, fd.task.transport, fd.task.allocator, fd.pure, buf))

class SeekableFile(File):
    pass

class ReadableWritableFile(ReadableFile, WritableFile):
    pass

class SignalFile(ReadableFile):
    def __init__(self, mask: t.Set[signal.Signals], shared=False) -> None:
        super().__init__(shared=shared)
        self.mask = mask

    async def signalfd(self, fd: 'FileDescriptor[SignalFile]', mask: t.Set[signal.Signals]) -> None:
        await memsys.signalfd(fd.task.syscall, fd.task.transport, fd.task.allocator, mask, 0, fd=fd.pure)
        self.mask = mask

class DirectoryFile(SeekableFile):
    def __init__(self, raw_path: base.Path) -> None:
        # this is a fallback if we need to serialize this dirfd out
        self.raw_path = raw_path

    async def getdents(self, fd: 'FileDescriptor[DirectoryFile]', count: int) -> t.List[Dirent]:
        return (await fd.task.getdents(fd.handle.far, count))

    def as_path(self, fd: FileDescriptor[DirectoryFile]) -> Path:
        return Path(fd.task, handle.Path(fd.handle, []))

class SocketFile(t.Generic[T_addr], ReadableWritableFile):
    address_type: t.Type[T_addr]

    async def bind(self, fd: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await memsys.bind(fd.task.syscall, fd.task.transport, fd.task.allocator, fd.pure, addr.to_bytes())

    async def listen(self, fd: 'FileDescriptor[SocketFile]', backlog: int) -> None:
        await raw_syscall.listen(fd.task.syscall, fd.pure, backlog)

    async def connect(self, fd: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await memsys.connect(fd.task.syscall, fd.task.transport, fd.task.allocator, fd.pure, addr.to_bytes())

    async def getsockname(self, fd: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        data = await memsys.getsockname(fd.task.syscall, fd.task.transport, fd.task.allocator, fd.pure, self.address_type.addrlen)
        return self.address_type.parse(data)

    async def getpeername(self, fd: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        data = await memsys.getpeername(fd.task.syscall, fd.task.transport, fd.task.allocator, fd.pure, self.address_type.addrlen)
        return self.address_type.parse(data)

    async def getsockopt(self, fd: 'FileDescriptor[SocketFile[T_addr]]', level: int, optname: int, optlen: int) -> bytes:
        return (await memsys.getsockopt(fd.task.syscall, fd.task.transport, fd.task.allocator, fd.pure, level, optname, optlen))

    async def setsockopt(self, fd: 'FileDescriptor[SocketFile[T_addr]]', level: int, optname: int, optval: bytes) -> None:
        return (await memsys.setsockopt(fd.task.syscall, fd.task.transport, fd.task.allocator, fd.pure, level, optname, optval))

    async def accept(self, fd: 'FileDescriptor[SocketFile[T_addr]]', flags: int) -> t.Tuple['FileDescriptor[SocketFile[T_addr]]', T_addr]:
        fdnum, data = await memsys.accept(fd.task.syscall, fd.task.transport, fd.task.allocator,
                                          fd.pure, self.address_type.addrlen, flags)
        addr = self.address_type.parse(data)
        fd = fd.task.make_fd(near.FileDescriptor(fdnum), type(self)())
        return fd, addr

class UnixSocketFile(SocketFile[UnixAddress]):
    address_type = UnixAddress

class InetSocketFile(SocketFile[InetAddress]):
    address_type = InetAddress

class FileDescriptor(t.Generic[T_file_co]):
    "A file descriptor, plus a task to access it from, plus the file object underlying the descriptor."
    task: Task
    file: T_file_co
    def __init__(self, task: Task, handle: handle.FileDescriptor, file: T_file_co) -> None:
        self.task = task
        self.handle = handle
        self.file = file
        self.pure = handle.far
        self.open = True

    async def aclose(self):
        if self.open:
            await raw_syscall.close(self.task.syscall, self.pure)
            self.open = False
        else:
            pass

    def __str__(self) -> str:
        return f'FD({self.task}, {self.pure}, {self.file})'

    async def __aenter__(self) -> 'FileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    def release(self) -> 'FileDescriptor[T_file_co]':
        """Disassociate the file descriptor from this object

        """
        if self.open:
            self.open = False
            return self.__class__(self.task, self.handle, self.file)
        else:
            raise Exception("file descriptor already closed")

    def borrow(self, task: base.Task) -> 'FileDescriptor[T_file_co]':
        """Disassociate the file descriptor from this object

        """
        if self.open:
            return self.__class__(self.task, task.make_fd_handle(self.handle), self.file)
        else:
            raise Exception("file descriptor already closed")

    async def dup2(self, target: 'FileDescriptor') -> 'FileDescriptor[T_file_co]':
        """Make a copy of this file descriptor at target.number

        """
        if self.pure.fd_table != target.pure.fd_table:
            raise Exception("two fds are not in the same FDTable")
        if self is target:
            return self
        await raw_syscall.dup3(self.task.syscall, self.pure, target.pure, 0)
        target.open = False
        new_fd = self.task.make_fd(target.handle.near, self.file)
        # dup2 unsets cloexec on the new copy, so:
        self.file.shared = True
        return new_fd

    async def move_to(self, target: 'FileDescriptor') -> 'FileDescriptor[T_file_co]':
        ret = await self.dup2(target)
        await self.aclose()
        return ret

    async def replace_with(self, source: handle.FileDescriptor, flags=0) -> None:
        if self.handle.task.fd_table != source.task.fd_table:
            raise Exception("two fds are not in the same file descriptor tables",
                            self.handle.task.fd_table, source.task.fd_table)
        if self.handle.near == source.near:
            return
        await source.dup3(self.handle, flags)
        await source.invalidate()

    async def as_argument(self) -> int:
        # TODO unset cloexec
        await self.disable_cloexec()
        return self.handle.near.number

    async def enable_cloexec(self) -> None:
        raise NotImplementedError

    async def disable_cloexec(self) -> None:
        await raw_syscall.fcntl(self.task.syscall, self.pure, fcntl.F_SETFD, 0)

    # These are just helper methods which forward to the method on the underlying file object.
    async def set_nonblock(self: 'FileDescriptor[File]') -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        await self.file.set_nonblock(self)

    async def read(self: 'FileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        return (await self.file.read(self, count))

    async def write(self: 'FileDescriptor[WritableFile]', buf: bytes) -> int:
        return (await self.file.write(self, buf))

    async def add(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor', event: Pointer) -> None:
        await self.file.add(self, fd, event)

    async def modify(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor', event: Pointer) -> None:
        await self.file.modify(self, fd, event)

    async def delete(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor') -> None:
        await self.file.delete(self, fd)

    async def wait(self: 'FileDescriptor[EpollFile]',
                   events: Pointer, maxevents: int, timeout: int) -> int:
        return (await self.file.wait(self, events, maxevents, timeout))

    async def getdents(self: 'FileDescriptor[DirectoryFile]', count: int=4096) -> t.List[Dirent]:
        return (await self.file.getdents(self, count))

    def as_path(self: FileDescriptor[DirectoryFile]) -> Path:
        return self.file.as_path(self)

    async def lseek(self: 'FileDescriptor[SeekableFile]', offset: int, whence: int) -> int:
        return (await self.file.lseek(self, offset, whence))

    async def signalfd(self: 'FileDescriptor[SignalFile]', mask: t.Set[signal.Signals]) -> None:
        await self.file.signalfd(self, mask)

    async def bind(self: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await self.file.bind(self, addr)

    async def listen(self: 'FileDescriptor[SocketFile]', backlog: int) -> None:
        await self.file.listen(self, backlog)

    async def connect(self: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await self.file.connect(self, addr)

    async def getsockname(self: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        return (await self.file.getsockname(self))

    async def getpeername(self: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        return (await self.file.getpeername(self))

    async def getsockopt(self: 'FileDescriptor[SocketFile[T_addr]]', level: int, optname: int, optlen: int) -> bytes:
        return (await self.file.getsockopt(self, level, optname, optlen))

    async def accept(self: 'FileDescriptor[SocketFile[T_addr]]', flags: int) -> t.Tuple['FileDescriptor[SocketFile[T_addr]]', T_addr]:
        return (await self.file.accept(self, flags))

class EpollFile(File):
    async def add(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor, event: Pointer) -> None:
        await raw_syscall.epoll_ctl(epfd.task.syscall, epfd.pure, EpollCtlOp.ADD, fd.pure, event)

    async def modify(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor, event: Pointer) -> None:
        await raw_syscall.epoll_ctl(epfd.task.syscall, epfd.pure, EpollCtlOp.MOD, fd.pure, event)

    async def delete(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor) -> None:
        await raw_syscall.epoll_ctl(epfd.task.syscall, epfd.pure, EpollCtlOp.DEL, fd.pure)

    async def wait(self, epfd: 'FileDescriptor[EpollFile]',
                   events: Pointer, maxevents: int, timeout: int) -> int:
        return (await raw_syscall.epoll_wait(epfd.task.syscall, epfd.pure, events, maxevents, timeout))

class EpolledFileDescriptor:
    def __init__(self,
                 epoll_center: EpollCenter,
                 fd: handle.FileDescriptor,
                 queue: trio.abc.ReceiveChannel,
                 number: int) -> None:
        self.epoll_center = epoll_center
        self.fd = fd
        self.queue = queue
        self.number = number
        self.in_epollfd = True

    async def modify(self, events: EpollEventMask) -> None:
        await self.epoll_center.modify(self.fd.far, EpollEvent(self.number, events))

    async def wait(self) -> t.List[EpollEvent]:
        while True:
            try:
                return [self.queue.receive_nowait()]
            except trio.WouldBlock:
                await self.epoll_center.epoller.do_wait()

    async def aclose(self) -> None:
        if self.in_epollfd:
            # TODO hmm, I guess we need to serialize this removal with calls to epoll?
            await self.epoll_center.delete(self.fd.far)
            self.in_epollfd = False

class EpollCenter:
    "Terribly named class that allows registering fds on epoll, and waiting on them"
    def __init__(self, epoller: EpollWaiter, epfd: handle.FileDescriptor,
                 transport: base.MemoryTransport, allocator: memory.AllocatorInterface) -> None:
        self.epoller = epoller
        self.epfd = epfd
        self.transport = transport
        self.allocator = allocator

    async def register(self, fd: handle.FileDescriptor, events: EpollEventMask=None) -> EpolledFileDescriptor:
        if events is None:
            events = EpollEventMask.make()
        send, receive = trio.open_memory_channel(math.inf)
        number = self.epoller.add_and_allocate_number(send)
        await self.add(fd.far, EpollEvent(number, events))
        return EpolledFileDescriptor(self, fd, receive, number)

    async def add(self, fd: far.FileDescriptor, event: EpollEvent) -> None:
        await memsys.epoll_ctl_add(self.epfd.task, self.transport, self.allocator, self.epfd.far, fd, event)

    async def modify(self, fd: far.FileDescriptor, event: EpollEvent) -> None:
        await memsys.epoll_ctl_mod(self.epfd.task, self.transport, self.allocator, self.epfd.far, fd, event)

    async def delete(self, fd: far.FileDescriptor) -> None:
        await memsys.epoll_ctl_del(self.epfd.task, self.epfd.far, fd)

@dataclass
class PendingEpollWait:
    allocation: memory.Allocation
    syscall_response: near.SyscallResponse
    memory_transport: base.MemoryTransport
    received_events: t.Optional[t.List[EpollEvent]] = None

    async def receive(self) -> t.List[EpollEvent]:
        if self.received_events is not None:
            return self.received_events
        else:
            count = await self.syscall_response.receive()
            bufsize = self.allocation.end - self.allocation.start
            localbuf = await self.memory_transport.read(self.allocation.pointer, bufsize)
            ret: t.List[EpollEvent] = []
            cur = 0
            for _ in range(count):
                ret.append(EpollEvent.from_bytes(localbuf[cur:cur+EpollEvent.bytesize()]))
                cur += EpollEvent.bytesize()
            self.received_events = ret
            self.allocation.free()
            return ret

class EpollWaiter:
    def __init__(self, epfd: FileDescriptor[EpollFile],
                 wait_readable: t.Optional[t.Callable[[], t.Awaitable[None]]]) -> None:
        self.waiting_task = epfd.task
        self.epfd = epfd
        self.wait_readable = wait_readable
        self.next_number = 0
        self.number_to_queue: t.Dict[int, trio.abc.SendChannel] = {}
        self.running_wait: t.Optional[trio.Event] = None
        self.pending_epoll_wait: t.Optional[PendingEpollWait] = None

    # need to also support removing, I guess!
    def add_and_allocate_number(self, queue: trio.abc.SendChannel) -> int:
        number = self.next_number
        self.next_number += 1
        self.number_to_queue[number] = queue
        return number

    async def do_wait(self) -> None:
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait
            try:
                if self.wait_readable is not None:
                    # yield away first
                    await trio.sleep(0)
                    received_events = await self.wait(maxevents=32, timeout=0)
                    if len(received_events) == 0:
                        await self.wait_readable()
                        # We are only guaranteed to receive events from the following line because
                        # we are careful in our usage of epoll.  Some background: Given that we are
                        # using EPOLLET, we can view epoll_wait as providing us a stream of posedges
                        # for readability, writability, etc. We receive negedges in the form of
                        # EAGAINs when we try to read, write, etc.

                        # We could try to optimistically read or write without first receiving a
                        # posedge from epoll. If the read/write succeeds, that serves as a
                        # posedge. Importantly, that posedge might not then be delivered through
                        # epoll.  The posedge is definitely not delivered through epoll if the fd is
                        # read to EAGAIN before the next epoll call, and may also not be delivered
                        # in other scenarios as well.

                        # This can cause deadlocks.  If a thread is blocked in epoll waiting for
                        # some file to become readable, and some other thread goes ahead and reads
                        # off the posedge from the file itself, then the first thread will never get
                        # woken up since epoll will never have an event for readability.

                        # Also, epoll will be indicated as readable to poll when a posedge is ready
                        # for reading; but if we consume that posedge through reading the fd
                        # directly instead, we won't actually get anything when we call epoll_wait.

                        # Therefore, we must make sure to receive all posedges exclusively through
                        # epoll. We can't optimistically read the file descriptor before we have
                        # actually received an initial posedge. (This doesn't hurt performance that
                        # much because we can still optimistically read the fd if we haven't yet
                        # seen an EAGAIN since the last epoll_wait posedge.)

                        # Given that we follow that behavior, we are guaranteed here to get some
                        # event, since wait_readable returning has informed us that there is a
                        # posedge to be read, and all posedges are consume exclusively through
                        # epoll.
                        received_events = await self.wait(maxevents=32, timeout=0)
                        if len(received_events) == 0:
                            raise Exception("got no events back from epoll_wait even after epfd was indicated as readable")
                else:
                    if self.pending_epoll_wait is None:
                        pending = await self.submit_wait(maxevents=32, timeout=-1)
                        self.pending_epoll_wait = pending
                    else:
                        pending = self.pending_epoll_wait
                    received_events = await pending.receive()
                    self.pending_epoll_wait = None
                for event in received_events:
                    queue = self.number_to_queue[event.data]
                    queue.send_nowait(event.events)
            finally:
                self.running_wait = None
                running_wait.set()

    async def submit_wait(self, maxevents: int, timeout: int) -> PendingEpollWait:
        allocation = await self.waiting_task.allocator.malloc(maxevents * EpollEvent.bytesize())
        try:
            syscall_response = await self.epfd.handle.task.sysif.submit_syscall(
                near.SYS.epoll_wait, self.epfd.handle.near, allocation.pointer, maxevents, timeout)
        except:
            allocation.free()
            raise
        else:
            return PendingEpollWait(allocation, syscall_response, self.waiting_task.transport)

    async def wait(self, maxevents: int, timeout: int) -> t.List[EpollEvent]:
        bufsize = maxevents * EpollEvent.bytesize()
        with await self.waiting_task.allocator.malloc(bufsize) as events_ptr:
            count = await self.epfd.wait(events_ptr, maxevents, timeout)
            with trio.open_cancel_scope(shield=True):
                localbuf = await self.waiting_task.transport.read(events_ptr, bufsize)
        ret: t.List[EpollEvent] = []
        cur = 0
        for _ in range(count):
            ret.append(EpollEvent.from_bytes(localbuf[cur:cur+EpollEvent.bytesize()]))
            cur += EpollEvent.bytesize()
        return ret

class AsyncFileDescriptor(t.Generic[T_file_co]):
    epolled: EpolledFileDescriptor

    @staticmethod
    async def make(epoller: EpollCenter, fd: FileDescriptor[T_file], is_nonblock=False) -> 'AsyncFileDescriptor[T_file]':
        if not is_nonblock:
            await fd.set_nonblock()
        epolled = await epoller.register(fd.handle, EpollEventMask.make(
            in_=True, out=True, rdhup=True, pri=True, err=True, hup=True, et=True))
        return AsyncFileDescriptor(epolled, fd)

    def __init__(self, epolled: EpolledFileDescriptor, underlying: FileDescriptor[T_file_co]) -> None:
        self.epolled = epolled
        self.underlying = underlying
        self.running_wait: t.Optional[trio.Event] = None
        self.is_readable = False
        self.is_writable = False
        self.read_hangup = False
        self.priority = False
        self.error = False
        self.hangup = False

    async def _wait_once(self):
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait
            try:
                events = await self.epolled.wait()
                for event in events:
                    if event.in_:   self.is_readable = True
                    if event.out:   self.is_writable = True
                    if event.rdhup: self.read_hangup = True
                    if event.pri:   self.priority = True
                    if event.err:   self.error = True
                    if event.hup:   self.hangup = True
            finally:
                self.running_wait = None
                running_wait.set()

    def could_read(self) -> bool:
        return self.is_readable or self.read_hangup or self.hangup or self.error

    async def read_nonblock(self: 'AsyncFileDescriptor[ReadableFile]', count: int=4096) -> t.Optional[bytes]:
        if not self.could_read():
            return None
        try:
            return (await self.underlying.read(count))
        except OSError as e:
            if e.errno == errno.EAGAIN:
                self.is_readable = False
                return None
            else:
                raise

    async def read(self: 'AsyncFileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        while True:
            while not self.could_read():
                await self._wait_once()
            data = await self.read_nonblock()
            if data is not None:
                return data

    async def read_raw(self, sysif: near.SyscallInterface, fd: near.FileDescriptor, pointer: near.Pointer, count: int) -> int:
        while True:
            while not self.could_read():
                await self._wait_once()
            try:
                return (await near.read(sysif, fd, pointer, count))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                else:
                    raise

    async def write(self: 'AsyncFileDescriptor[WritableFile]', buf: bytes) -> None:
        while len(buf) > 0:
            while not (self.is_writable or self.error):
                await self._wait_once()
            try:
                written = await self.underlying.write(buf)
                buf = buf[written:]
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    # TODO this is not really quite right if it's possible to concurrently call methods on this object.
                    # we really need to lock while we're making the async call, right? maybe...
                    self.is_writable = False
                else:
                    raise

    async def write_raw(self, sysif: near.SyscallInterface, fd: near.FileDescriptor, pointer: near.Pointer, count: int) -> int:
        while True:
            while not (self.is_writable or self.error):
                await self._wait_once()
            try:
                return (await near.write(sysif, fd, pointer, count))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    # TODO this is not really quite right if it's possible to concurrently call methods on this object.
                    # we really need to lock while we're making the async call, right? maybe...
                    self.is_writable = False
                else:
                    raise

    async def accept(self: 'AsyncFileDescriptor[SocketFile[T_addr]]', flags: int=lib.SOCK_CLOEXEC
    ) -> t.Tuple[FileDescriptor[SocketFile[T_addr]], T_addr]:
        while True:
            while not (self.is_readable or self.hangup):
                await self._wait_once()
            try:
                return (await self.underlying.accept(flags))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                else:
                    raise

    async def connect(self: 'AsyncFileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        try:
            await self.underlying.connect(addr)
        except OSError as e:
            if e.errno == errno.EINPROGRESS:
                while not self.is_writable:
                    await self._wait_once()
                retbuf = await self.underlying.getsockopt(lib.SOL_SOCKET, lib.SO_ERROR, ffi.sizeof('int'))
                err = ffi.cast('int*', ffi.from_buffer(retbuf))[0]
                if err != 0:
                    raise OSError(err, os.strerror(err))
            else:
                raise

    async def aclose(self) -> None:
        pass

class Path:
    "This is a convenient combination of a Path and a Task to perform serialization."
    def __init__(self, task: Task, handle: handle.Path) -> None:
        self.task = task
        self.handle = handle

    @property
    def pure(self) -> far.Path:
        return self.handle.far

    def split(self) -> t.Tuple[Path, bytes]:
        dir, name = self.handle.split()
        return Path(self.task, dir), name

    @staticmethod
    def from_bytes(task: Task, path: bytes) -> Path:
        return Path(task, task.base.make_path_from_bytes(path))

    async def mkdir(self, mode=0o777) -> Path:
        await memsys.mkdirat(self.task.syscall, self.task.transport, self.task.allocator,
                             self.pure, mode)
        return self

    async def open(self, flags: int, mode=0o644) -> FileDescriptor:
        """Open a path

        Note that this can block forever if we're opening a FIFO

        """
        file: File
        if flags & os.O_PATH:
            file = File()
        elif flags & os.O_WRONLY:
            file = WritableFile()
        elif flags & os.O_RDWR:
            file = ReadableWritableFile()
        elif flags & os.O_DIRECTORY:
            file = DirectoryFile(self.pure)
        else:
            # os.O_RDONLY is 0, so if we don't have any of the rest, then...
            file = ReadableFile()
        fd = await memsys.openat(self.task.syscall, self.task.transport, self.task.allocator,
                                 self.pure, flags, mode)
        return self.task.make_fd(fd, file)

    async def open_directory(self) -> FileDescriptor[DirectoryFile]:
        return (await self.open(os.O_DIRECTORY))

    async def open_path(self) -> FileDescriptor[File]:
        return (await self.open(os.O_PATH))

    async def creat(self, mode=0o644) -> FileDescriptor[WritableFile]:
        fd = await memsys.openat(self.task.syscall, self.task.transport, self.task.allocator,
                                 self.pure, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, mode)
        return self.task.make_fd(fd, WritableFile())

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
        try:
            await memsys.faccessat(self.task.syscall, self.task.transport, self.task.allocator,
                                   self.pure, mode, 0)
            return True
        except OSError:
            return False

    async def unlink(self, flags: int=0) -> None:
        await memsys.unlinkat(self.task.syscall, self.task.transport, self.task.allocator,
                              self.pure, flags)

    async def rmdir(self) -> None:
        await memsys.unlinkat(self.task.syscall, self.task.transport, self.task.allocator,
                              self.pure, rsyscall.stat.AT_REMOVEDIR)

    async def link(self, oldpath: 'Path', flags: int=0) -> 'Path':
        "Create a hardlink at Path 'self' to the file at Path 'oldpath'"
        await memsys.linkat(self.task.syscall, self.task.transport, self.task.allocator,
                            oldpath.pure, self.pure, flags)
        return self

    async def symlink(self, target: bytes) -> 'Path':
        "Create a symlink at Path 'self' pointing to the passed-in target"
        await memsys.symlinkat(self.task.syscall, self.task.transport, self.task.allocator,
                               self.pure, target)
        return self


    async def rename(self, oldpath: 'Path', flags: int=0) -> 'Path':
        "Create a file at Path 'self' by renaming the file at Path 'oldpath'"
        await memsys.renameat(self.task.syscall, self.task.transport, self.task.allocator,
                              oldpath.pure, self.pure, flags)
        return self

    async def readlink(self, bufsiz: int=4096) -> bytes:
        return (await memsys.readlinkat(self.task.syscall, self.task.transport, self.task.allocator,
                                        self.pure, bufsiz))
    
    def _as_proc_path(self) -> bytes:
        return self.handle.far._as_proc_path()

    async def as_argument(self) -> bytes:
        if isinstance(self.handle.base, handle.FileDescriptor):
            # we disable cloexec to pass the dirfd as an argument.
            # this is somewhat weird to do without ownership, but whatever.
            await self.handle.base.fcntl(fcntl.F_SETFD, 0)
        return self._as_proc_path()

    def unix_address(self) -> UnixAddress:
        """Return an address that can be used with bind/connect for Unix sockets

        Linux doesn't support bindat/connectat or similar, so this is emulated with /proc.

        This will throw PathTooLongError if the bytes component of the
        path is too long, because bind/connect have a limit of 108
        bytes for the pathname.

        """
        return UnixAddress(self._as_proc_path())

    def __truediv__(self, path_element: t.Union[str, bytes]) -> Path:
        return Path(self.task, self.handle/path_element)

    def __str__(self) -> str:
        return f"Path({self.pure})"

async def robust_unix_bind(path: Path, sock: FileDescriptor[UnixSocketFile]) -> None:
    """Perform a Unix socket bind, hacking around the 108 byte limit on socket addresses.

    If the passed path is too long to fit in an address, this function will open the path's
    directory with O_PATH, and bind to /proc/self/fd/n/{pathname}; if that's still too long due to
    pathname being too long, this function will call robust_unix_bind_helper to bind to a temporary
    name and rename the resulting socket to pathname.

    If you are going to be binding to this path repeatedly, it's more efficient to open the
    directory with O_PATH and call robust_unix_bind_helper yourself, rather than call into this
    function.

    """
    async with contextlib.AsyncExitStack() as stack:
        try:
            addr = path.unix_address()
        except PathTooLongError:
            dir, name = path.split()
            if not(isinstance(dir.handle.base, handle.FileDescriptor) and len(dir.pure.components) == 0):
                # shrink the dir path by opening it directly as a dirfd
                dirfd = await stack.enter_async_context(await dir.open_directory())
                dir = dirfd.as_path()
            await robust_unix_bind_helper(dir, name, sock)
        else:
            await sock.bind(addr)

async def robust_unix_bind_helper(dir: Path, name: bytes, sock: FileDescriptor[UnixSocketFile]) -> None:
    """Perform a Unix socket bind to dir/name, hacking around the 108 byte limit on socket addresses.

    If `dir'/`name' is too long to fit in an address, this function will instead bind to a temporary
    name in `dir', and then rename the resulting socket to `name'.

    Make sure outside this function that `dir' is sufficiently short for this to work - ideally `dir'
    should be based on a dirfd.

    TODO: This hack is actually semantically different from a normal direct bind: it's not
    atomic. That's tricky...

    """
    path = dir/name
    try:
        addr = path.unix_address()
    except PathTooLongError:
        # TODO randomly pick this name and retry if it's used
        tmppath = dir/"tmpsock"
        tmpaddr = tmppath.unix_address()
        await sock.bind(tmpaddr)
        await path.rename(tmppath)
    else:
        await sock.bind(addr)

async def robust_unix_connect(path: Path, sock: FileDescriptor[UnixSocketFile]) -> None:
    """Perform a Unix socket connect, hacking around the 108 byte limit on socket addresses.

    If the passed path is too long to fit in an address, this function will open that path with
    O_PATH and connect to /proc/self/fd/n.

    If you are going to be connecting to this path repeatedly, it's more efficient to open the path
    with O_PATH yourself rather than call into this function.

    """
    async with contextlib.AsyncExitStack() as stack:
        try:
            addr = path.unix_address()
        except PathTooLongError:
            # connectat with AT_EMPTY_PATH would make this cleaner
            pathfd = await stack.enter_async_context(await path.open_path())
            addr = UnixAddress(b"/".join([b"/proc/self/fd", str(pathfd.handle.near.number).encode()]))
        await sock.connect(addr)

async def fspath(arg: t.Union[str, bytes, Path]) -> bytes:
    if isinstance(arg, str):
        return os.fsencode(arg)
    elif isinstance(arg, bytes):
        return arg
    elif isinstance(arg, Path):
        return (await arg.as_argument())
    else:
        raise ValueError

@dataclass
class StandardStreams:
    stdin: FileDescriptor[ReadableFile]
    stdout: FileDescriptor[WritableFile]
    stderr: FileDescriptor[WritableFile]

@dataclass
class UnixBootstrap:
    """The resources traditionally given to a process on startup in Unix.

    These are not absolutely guaranteed; environ and stdstreams are
    both userspace conventions. Still, we will rely on this for our
    tasks.

    """
    task: Task
    argv: t.List[bytes]
    environ: t.Mapping[bytes, bytes]
    stdstreams: StandardStreams

def wrap_stdin_out_err(task: Task) -> StandardStreams:
    stdin = task._make_fd(0, ReadableFile(shared=True))
    stdout = task._make_fd(1, WritableFile(shared=True))
    stderr = task._make_fd(2, WritableFile(shared=True))
    return StandardStreams(stdin, stdout, stderr)

@dataclass
class UnixUtilities:
    rm: handle.Path
    sh: handle.Path
    ssh: SSHCommand

async def spit(path: Path, text: t.Union[str, bytes]) -> Path:
    """Open a file, creating and truncating it, and write the passed text to it

    Probably shouldn't use this on FIFOs or anything.

    Returns the passed-in Path so this serves as a nice pseudo-constructor.

    """
    data = os.fsencode(text)
    async with (await path.creat()) as fd:
        while len(data) > 0:
            ret = await fd.write(data)
            data = data[ret:]
    return path

@dataclass
class ProcessResources:
    server_func: FunctionPointer
    do_cloexec_func: FunctionPointer
    stop_then_close_func: FunctionPointer
    trampoline_func: FunctionPointer
    futex_helper_func: FunctionPointer

    async def decref(self) -> None:
        pass

    @staticmethod
    def make_from_symbols(symbols: t.Mapping[bytes, far.Pointer]) -> ProcessResources:
        return ProcessResources(
            server_func=FunctionPointer(symbols[b"rsyscall_server"]),
            do_cloexec_func=FunctionPointer(symbols[b"rsyscall_do_cloexec"]),
            stop_then_close_func=FunctionPointer(symbols[b"rsyscall_stop_then_close"]),
            trampoline_func=FunctionPointer(symbols[b"rsyscall_trampoline"]),
            futex_helper_func=FunctionPointer(symbols[b"rsyscall_futex_helper"]),
        )

    def build_trampoline_stack(self, function: FunctionPointer, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> bytes:
        # TODO clean this up with dicts or tuples or something
        stack_struct = ffi.new('struct rsyscall_trampoline_stack*')
        stack_struct.rdi = int(arg1)
        stack_struct.rsi = int(arg2)
        stack_struct.rdx = int(arg3)
        stack_struct.rcx = int(arg4)
        stack_struct.r8  = int(arg5)
        stack_struct.r9  = int(arg6)
        stack_struct.function = ffi.cast('void*', int(function.pointer.near))
        logger.info("trampoline_func %s", self.trampoline_func.pointer)
        packed_trampoline_addr = struct.pack('Q', int(self.trampoline_func.pointer.near))
        stack = packed_trampoline_addr + bytes(ffi.buffer(stack_struct))
        return stack

trampoline_stack_size = ffi.sizeof('struct rsyscall_trampoline_stack') + 8

local_process_resources = ProcessResources(
    server_func=FunctionPointer(base.cffi_to_local_pointer(lib.rsyscall_server)),
    do_cloexec_func=FunctionPointer(base.cffi_to_local_pointer(lib.rsyscall_do_cloexec)),
    stop_then_close_func=FunctionPointer(base.cffi_to_local_pointer(lib.rsyscall_stop_then_close)),
    trampoline_func=FunctionPointer(base.cffi_to_local_pointer(lib.rsyscall_trampoline)),
    futex_helper_func=FunctionPointer(base.cffi_to_local_pointer(lib.rsyscall_futex_helper)),
)

@dataclass
class FilesystemResources:
    tmpdir: handle.Path
    utilities: UnixUtilities
    # locale?
    # home directory?
    rsyscall_server_path: handle.Path
    socket_binder_path: handle.Path
    rsyscall_bootstrap_path: handle.Path

    @staticmethod
    def make_from_environ(task: handle.Task, environ: t.Mapping[bytes, bytes]) -> FilesystemResources:
        tmpdir = task.make_path_from_bytes(environ.get(b"TMPDIR", b"/tmp"))
        def cffi_to_path(cffi_char_array) -> handle.Path:
            return task.make_path_from_bytes(ffi.string(cffi_char_array))
        utilities = UnixUtilities(
            rm=cffi_to_path(lib.rm_path),
            sh=cffi_to_path(lib.sh_path),
            ssh=SSHCommand.make(cffi_to_path(lib.ssh_path)),
        )
        rsyscall_pkglibexecdir = cffi_to_path(lib.pkglibexecdir)
        rsyscall_server_path = rsyscall_pkglibexecdir/"rsyscall-server"
        socket_binder_path = rsyscall_pkglibexecdir/"socket-binder"
        rsyscall_bootstrap_path = rsyscall_pkglibexecdir/"rsyscall-bootstrap"
        return FilesystemResources(
            tmpdir=tmpdir,
            utilities=utilities,
            rsyscall_server_path=rsyscall_server_path,
            socket_binder_path=socket_binder_path,
            rsyscall_bootstrap_path=rsyscall_bootstrap_path,
        )

async def lookup_executable(paths: t.List[Path], name: bytes) -> Path:
    "Find an executable by this name in this list of paths"
    if b"/" in name:
        raise Exception("name should be a single path element without any / present")
    for path in paths:
        filename = path/name
        if (await filename.access(read=True, execute=True)):
            return filename
    raise Exception("executable not found", name)

async def which(stdtask: StandardTask, name: bytes) -> Command:
    "Find an executable by this name in PATH"
    executable_dirs: t.List[Path] = []
    for prefix in stdtask.environment[b"PATH"].split(b":"):
        executable_dirs.append(Path.from_bytes(stdtask.task, prefix))
    executable_path = await lookup_executable(executable_dirs, name)
    return Command(executable_path.handle, [name.decode()], {})

class StandardTask:
    def __init__(self,
                 access_task: Task,
                 access_epoller: EpollCenter,
                 access_connection: t.Optional[t.Tuple[Path, FileDescriptor[UnixSocketFile]]],
                 connecting_task: Task,
                 # TODO we need to lock this, and the access_connection also.
                 # they are shared between processes...
                 connecting_connection: t.Tuple[handle.FileDescriptor, handle.FileDescriptor],
                 task: Task,
                 process_resources: ProcessResources,
                 filesystem_resources: FilesystemResources,
                 epoller: EpollCenter,
                 child_monitor: ChildTaskMonitor,
                 local_epoller: EpollCenter,
                 environment: t.Dict[bytes, bytes],
                 stdin: FileDescriptor[ReadableFile],
                 stdout: FileDescriptor[WritableFile],
                 stderr: FileDescriptor[WritableFile],
    ) -> None:
        self.access_task = access_task
        self.access_epoller = access_epoller
        self.access_connection = access_connection
        self.connecting_task = connecting_task
        self.connecting_connection = connecting_connection
        self.task = task
        self.process = process_resources
        self.filesystem = filesystem_resources
        self.epoller = epoller
        self.child_monitor = child_monitor
        self.local_epoller = local_epoller
        self.environment = environment
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

    @staticmethod
    async def make_local() -> StandardTask:
        syscall = LocalSyscall()
        pid = os.getpid()
        # how do I make a socketpair without a socketpair...
        # guess I can just use the near syscall.
        # oh no I also need to register on the epoller, I can't do that.
        base_task = handle.Task(syscall, base.FDTable(pid), base.local_address_space,
                                far.FSInformation(pid, root=near.DirectoryFile(),
                                                  cwd=near.DirectoryFile()))
        task = Task(base_task,
                    LocalMemoryTransport(),
                    memory.AllocatorClient.make_allocator(base_task),
                    SignalMask(set()), far.ProcessNamespace(pid))
        environ = {key.encode(): value.encode() for key, value in os.environ.items()}
        stdstreams = wrap_stdin_out_err(task)

        # TODO fix this to... pull it from the bootstrap or something...
        process_resources = local_process_resources
        filesystem_resources = FilesystemResources.make_from_environ(base_task, environ)
        epoller = await task.make_epoll_center()
        child_monitor = await ChildTaskMonitor.make(task, epoller)
        # connection_listening_socket = await task.socket_unix(socket.SOCK_STREAM)
        # sockpath = Path.from_bytes(task, b"./rsyscall.sock")
        # await robust_unix_bind(sockpath, connection_listening_socket)
        # await connection_listening_socket.listen(10)
        # access_connection = (sockpath, connection_listening_socket)
        access_connection = None
        left_fd, right_fd = await task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        connecting_connection = (left_fd.handle, right_fd.handle)
        stdtask = StandardTask(
            task, epoller, access_connection,
            task, connecting_connection,
            task, process_resources, filesystem_resources,
            epoller, child_monitor, epoller,
            {**environ},
            stdstreams.stdin,
            stdstreams.stdout,
            stdstreams.stderr,
        )
        # We don't need this ourselves, but we keep it around so others can inherit it.
        [(access_sock, remote_sock)] = await stdtask.make_async_connections(1)
        task.transport = SocketMemoryTransport(access_sock, remote_sock, trio.Lock())
        return stdtask

    async def mkdtemp(self, prefix: str="mkdtemp") -> 'TemporaryDirectory':
        parent = Path(self.task, self.filesystem.tmpdir)
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = (prefix+"."+random_suffix).encode()
        await (parent/name).mkdir(mode=0o700)
        return TemporaryDirectory(self, parent, name)

    async def spawn_exec(self) -> RsyscallThread:
        rsyscall_thread = await self.fork()
        await rsyscall_exec(self, rsyscall_thread, self.filesystem.rsyscall_server_path)
        return rsyscall_thread

    async def make_async_connections(self, count: int) -> t.List[
            t.Tuple[AsyncFileDescriptor[ReadableWritableFile], handle.FileDescriptor]
    ]:
        conns = await self.make_connections(count)
        access_socks, local_socks = zip(*conns)
        async_access_socks = [await AsyncFileDescriptor.make(self.access_epoller, sock) for sock in access_socks]
        return list(zip(async_access_socks, local_socks))

    async def make_connections(self, count: int) -> t.List[
            t.Tuple[FileDescriptor[ReadableWritableFile], handle.FileDescriptor]
    ]:
        return (await make_connections(
            self.access_task, self.access_connection,
            self.connecting_task, self.connecting_connection,
            self.task, count))

    async def fork(self) -> RsyscallThread:
        [(access_sock, remote_sock)] = await self.make_async_connections(1)
        thread_maker = ThreadMaker(self.task, self.child_monitor, self.process)
        task, thread = await spawn_rsyscall_thread(
            access_sock, remote_sock,
            self.task, thread_maker, self.process.server_func)
        epoller = EpollCenter(self.epoller.epoller,
                              task.base.make_fd_handle(self.epoller.epfd),
                              task.transport, task.allocator)
        local_epoller = await task.make_epoll_center()
        signal_block = SignalBlock(task, {signal.SIGCHLD})
        # sadly we can't use an inherited signalfd, epoll doesn't want to add the same signalfd twice
        # TODO now we can use an inherited signalfd actually
        sigfd = await task.signalfd_create({signal.SIGCHLD}, flags=os.O_NONBLOCK)
        async_sigfd = await AsyncFileDescriptor.make(local_epoller, sigfd, is_nonblock=True)
        signal_queue = SignalQueue(signal_block, async_sigfd)
        child_task_monitor = ChildTaskMonitor(task, signal_queue)
        stdtask = StandardTask(
            self.access_task, self.access_epoller, self.access_connection,
            self.connecting_task,
            (self.connecting_connection[0], task.base.make_fd_handle(self.connecting_connection[1])),
            task, 
            self.process, self.filesystem,
            epoller, child_task_monitor, local_epoller,
            {**self.environment},
            stdin=self.stdin.borrow(task.base),
            stdout=self.stdout.borrow(task.base),
            stderr=self.stderr.borrow(task.base),
        )
        return RsyscallThread(stdtask, thread)

    async def unshare_files(self, going_to_exec=False) -> None:
        """Unshare the file descriptor table.

        Set going_to_exec to True if you are about to exec with this task; then we'll skip the
        manual CLOEXEC in userspace that we have to do to avoid keeping stray references around.

        TODO maybe this should return an object that lets us unset CLOEXEC on things?
        """
        async def do_unshare(close_in_old_space: t.List[near.FileDescriptor],
                             copy_to_new_space: t.List[near.FileDescriptor]) -> None:
            print("closing old", close_in_old_space)
            print("copying new", copy_to_new_space)
            await unshare_files(self.task, self.child_monitor, self.process,
                                close_in_old_space, copy_to_new_space, going_to_exec)
        await self.task.base.unshare_files(do_unshare)

    async def execve(self, path: Path, argv: t.Sequence[t.Union[str, bytes, Path]],
                     env_updates: t.Mapping[t.Union[str, bytes], t.Union[str, bytes, Path]]={},
    ) -> None:
        envp = {**self.environment}
        for key in env_updates:
            envp[os.fsencode(key)] = await fspath(env_updates[key])
        raw_envp: t.List[bytes] = []
        for key, value in envp.items():
            raw_envp.append(b''.join([key, b'=', value]))
        await self.task.execveat(path,
                                 [await fspath(arg) for arg in argv],
                                 raw_envp, flags=0)

    async def exit(self, status) -> None:
        await self.task.exit(0)

    async def close(self) -> None:
        await self.process.decref()
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
        cleanup_thread = await self.stdtask.fork()
        async with cleanup_thread:
            # TODO would be nice if unsharing the fs information gave us a cap to chdir
            await cleanup_thread.stdtask.task.chdir(self.parent)
            child = await cleanup_thread.execve(self.stdtask.filesystem.utilities.rm, ["rm", "-r", self.name])
            (await child.wait_for_exit()).check()

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
        await task.sigmask.block(task, mask)
        return SignalBlock(task, mask)

    def __init__(self, task: Task, mask: t.Set[signal.Signals]) -> None:
        self.task = task
        self.mask = mask

    async def close(self) -> None:
        await self.task.sigmask.unblock(self.task, self.mask)

    async def __aenter__(self) -> 'SignalBlock':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class SignalQueue:
    def __init__(self, signal_block: SignalBlock, sigfd: AsyncFileDescriptor[SignalFile]) -> None:
        self.signal_block = signal_block
        self.sigfd = sigfd

    @classmethod
    async def make(cls, task: Task, epoller: EpollCenter, mask: t.Set[signal.Signals]) -> 'SignalQueue':
        signal_block = await SignalBlock.make(task, mask)
        sigfd = await task.signalfd_create(mask)
        async_sigfd = await AsyncFileDescriptor.make(epoller, sigfd)
        return cls(signal_block, async_sigfd)

    async def read(self) -> t.Any:
        data = await self.sigfd.read()
        return ffi.cast('struct signalfd_siginfo*', ffi.from_buffer(data))

    async def close(self) -> None:
        await self.signal_block.close()
        await self.sigfd.aclose()

    async def __aenter__(self) -> 'SignalQueue':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class MultiplexerQueue:
    "This will be some kinda abstracted queue thing that can be used for epoll and for childtaskmonitor etc"
    # TODO
    # maybe we should, uhh
    # oh, we can't just check if someone is running and if they are, starting waiting on the queue
    # because, we need to get woken up to do the run if we're waiting
    # maybe that should be the thing, hmm
    # run this waiting function as long as someone is waiting on the queue
    # run in their time slice
    pass

class Multiplexer:
    pass

class ChildTask:
    def __init__(self, process: base.Process, queue: trio.hazmat.UnboundedQueue,
                 monitor: 'ChildTaskMonitor') -> None:
        self.process = process
        self.queue = queue
        self.monitor = monitor
        self.death_event: t.Optional[ChildEvent] = None

    async def wait(self) -> t.List[ChildEvent]:
        if self.death_event:
            raise Exception("child is already dead!")
        while True:
            try:
                events = self.queue.get_batch_nowait()
                for event in events:
                    if event.died():
                        self.death_event = event
                return events
            except trio.WouldBlock:
                await self.monitor.do_wait()

    def _flush_nowait(self) -> None:
        while True:
            try:
                events = self.queue.get_batch_nowait()
                for event in events:
                    if event.died():
                        self.death_event = event
            except trio.WouldBlock:
                return
        

    async def wait_for_exit(self) -> ChildEvent:
        if self.death_event:
            return self.death_event
        while True:
            for event in (await self.wait()):
                if event.died():
                    return event

    async def wait_for_stop_or_exit(self) -> ChildEvent:
        while True:
            for event in (await self.wait()):
                if event.died():
                    return event
                elif event.code == ChildCode.STOPPED:
                    return event

    @property
    def syscall(self) -> SyscallInterface:
        return self.monitor.signal_queue.sigfd.underlying.task.syscall

    @contextlib.asynccontextmanager
    async def get_pid(self) -> t.AsyncGenerator[t.Optional[base.Process], None]:
        """Returns the underlying process, or None if it's already dead.

        Operating on the pid of a child process requires taking the wait_lock to make sure
        the process's zombie is not collected while we're using its pid.

        """
        # TODO this could really be a reader-writer lock, with this use as the reader and
        # wait as the writer.
        async with self.monitor.wait_lock:
            self._flush_nowait()
            if self.death_event:
                yield None
            else:
                yield self.process

    async def send_signal(self, sig: signal.Signals) -> None:
        async with self.get_pid() as process:
            if process:
                await raw_syscall.kill(self.syscall, process, sig)
            else:
                raise Exception("child is already dead!")

    async def kill(self) -> None:
        async with self.get_pid() as process:
            if process:
                await raw_syscall.kill(self.syscall, process, signal.SIGKILL)

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        if self.death_event:
            pass
        else:
            await self.kill()
            await self.wait_for_exit()

class ChildTaskMonitor:
    @staticmethod
    async def make(task: Task, epoller: EpollCenter) -> 'ChildTaskMonitor':
        signal_queue = await SignalQueue.make(task, epoller, {signal.SIGCHLD})
        return ChildTaskMonitor(task, signal_queue)

    def __init__(self, waiting_task: Task, signal_queue: SignalQueue) -> None:
        self.waiting_task = waiting_task
        self.signal_queue = signal_queue
        self.task_map: t.Dict[int, ChildTask] = {}
        self.unknown_queue = trio.hazmat.UnboundedQueue()
        self.wait_lock = trio.Lock()
        if self.signal_queue.sigfd.underlying.file.mask != set([signal.SIGCHLD]):
            raise Exception("ChildTaskMonitor should get a SignalQueue only for SIGCHLD")
        self.running_wait: t.Optional[trio.Event] = None
        self.can_waitid = False

    async def clone(self,
                    clone_task: base.Task,
                    flags: int,
                    child_stack: Pointer, ctid: Pointer, newtls: Pointer) -> ChildTask:
        if clone_task != self.waiting_task.base:
            # We take a CLONE_TASK argument to allow for future use of multithreading or
            # CLONE_PARENT, but currently we just enforce it matches the waiting_task.
            raise Exception("tried to clone from task", clone_task,
                            "which doesn't matching waiting_task", self.waiting_task)
        # We need to serialize waits and clones, otherwise we could collect the child process zombie
        # before we even create the ChildTask object. if we did multiple clones and pid wrapped to
        # the same pid, we would then have no idea which child events belong to which child.
        # 
        # For us, wait_lock is sufficient serialization, since the only thing that can create new
        # child for this task, is this task itself. But note that if we're using CLONE_PARENT in a
        # child, or we're cloning in multiple threads, then we can run into this race.
        # 
        # This is mitigated in conventional multithreading using ctid/ptid, so we can look up the
        # pid in memory before clone returns or actually starts the thread. I don't know of any
        # efficient mitigation for the race when using CLONE_PARENT, so we can't use that flag.
        # Which is unfortunate, because CLONE_PARENT would be useful, it would allow us to skip
        # creating a ChildTaskMonitor in child processes.
        async with self.wait_lock:
            tid = await raw_syscall.clone(clone_task.sysif, flags, child_stack,
                                          ptid=None, ctid=ctid, newtls=newtls)
            # TODO this is wrong! we need to pull the process namespace out of the cloning task!
            # but it's not yet present on base.Task, so...
            process = base.Process(self.waiting_task.process_namespace, near.Process(tid))
            child_task = ChildTask(process, trio.hazmat.UnboundedQueue(), self)
            self.task_map[tid] = child_task
        return child_task

    async def do_wait(self) -> None:
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait
            try:
                if not self.can_waitid:
                    # we don't care what information we get from the signal, we just want to
                    # sleep until a SIGCHLD happens
                    await self.signal_queue.read()
                    self.can_waitid = True
                # loop on waitid to flush all child events
                task = self.waiting_task
                # TODO if we could just detect when the ChildTask that we are wait()ing for
                # has gotten an event, we could handle events in this function indefinitely,
                # and only return once we've sent an event to that ChildTask.
                # maybe by passing in the waiting queue?
                # could do the same for epoll too.
                # though we have to wake other people up too...
                try:
                    # have to serialize against things which use pids; we can't do a wait
                    # while something else is making a syscall with a pid, because we
                    # might collect the zombie for that pid and cause pid reuse
                    async with self.wait_lock:
                        siginfo = await memsys.waitid(
                            task.syscall, task.transport, task.allocator,
                            None, lib._WALL|lib.WEXITED|lib.WSTOPPED|lib.WCONTINUED|lib.WNOHANG)
                except ChildProcessError:
                    # no more children
                    logger.info("no more children")
                    self.can_waitid = False
                    return
                struct = ffi.cast('siginfo_t*', ffi.from_buffer(siginfo))
                if struct.si_pid == 0:
                    # no more waitable events, but we still have children
                    logger.info("no more waitable events")
                    self.can_waitid = False
                    return
                child_event = ChildEvent.make(ChildCode(struct.si_code),
                                              pid=int(struct.si_pid), uid=int(struct.si_uid),
                                              status=int(struct.si_status))
                logger.info("got child event %s", child_event)
                if child_event.pid in self.task_map:
                    self.task_map[child_event.pid].queue.put_nowait(child_event)
                else:
                    # some unknown child. this will happen if we're a subreaper, as
                    # things get reparented to us and die
                    self.unknown_queue.put_nowait(child_event)
                if child_event.died():
                    # this child is dead. if its pid is reused, we don't want to send
                    # any more events to the same ChildTask.
                    del self.task_map[child_event.pid]
            finally:
                self.running_wait = None
                running_wait.set()

    async def close(self) -> None:
        await self.signal_queue.close()

    async def __aenter__(self) -> 'ChildTaskMonitor':
        return self

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()

class Thread:
    """A thread is a child task currently running in the address space of its parent.

    This means:
    1. We have probably allocated memory for it, including a stack and thread-local storage.
    2. We need to free that memory when the task stops existing (by calling exit or receiving a signal)
    3. We need to free that memory when the task calls exec (and leaves our address space)

    We can straightforwardly achieve 2 by monitoring SIGCHLD/waitid for the task.

    To achieve 3, we need some reliable way to know when the task has successfully called
    exec. Since a thread can exec an arbitrary executable, we can't rely on the task notifying us
    when it has finished execing.

    We effectively want to be notified on mm_release. To achieve this, we use CLONE_CHILD_CLEARTID,
    which causes the task to do a futex wakeup on a specified address when it calls mm_release, and
    dedicate another task to waiting on that futex address.

    The purpose of this class, then, is to hold the resources necessary to be notified of
    mm_release. Namely, the futex.

    It would better if we could just get notified of mm_release through SIGCHLD/waitid.

    """
    child_task: ChildTask
    futex_task: ChildTask
    futex_mapping: handle.MemoryMapping
    def __init__(self, child_task: ChildTask, futex_task: ChildTask, futex_mapping: handle.MemoryMapping) -> None:
        self.child_task = child_task
        self.futex_task = futex_task
        self.futex_mapping = futex_mapping
        self.released = False

    async def execveat(self, sysif: SyscallInterface, transport: base.MemoryTransport, allocator: memory.AllocatorInterface,
                       path: handle.Path, argv: t.List[bytes], envp: t.List[bytes], flags: int) -> ChildTask:
        await memsys.execveat(sysif, transport, allocator, path.far, argv, envp, flags)
        return self.child_task

    async def wait_for_mm_release(self) -> ChildTask:
        """Wait for the task to leave the parent's address space, and return the ChildTask.

        The task can leave the parent's address space either by exiting or execing.

        """
        # once the futex task has exited, the child task has left the parent's address space.
        result = await self.futex_task.wait_for_exit()
        if not result.clean():
            raise Exception("the futex task", self.futex_task, "for child task", self.child_task,
                            "unexpectedly exited non-zero", result, "maybe it was SIGKILL'd?")
        await self.futex_mapping.munmap()
        self.released = True
        return self.child_task

    async def close(self) -> None:
        if not self.released:
            await self.child_task.kill()
            await self.wait_for_mm_release()

    async def __aenter__(self) -> 'Thread':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class CThread(Thread):
    """A thread running the C runtime and some C function.

    At the moment, that means it has a stack. 
    The considerations for the Thread class all therefore apply.

    TODO thread-local-storage.

    """
    stack_mapping: memory.AnonymousMapping
    def __init__(self, thread: Thread, stack_mapping: memory.AnonymousMapping) -> None:
        super().__init__(thread.child_task, thread.futex_task, thread.futex_mapping)
        self.stack_mapping = stack_mapping

    async def wait_for_mm_release(self) -> ChildTask:
        result = await super().wait_for_mm_release()
        # we can free the stack mapping now that the thread has left our address space
        await self.stack_mapping.unmap()
        return result

    async def __aenter__(self) -> 'CThread':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class BufferedStack:
    def __init__(self, base: Pointer) -> None:
        self.base = base
        self.allocation_pointer = self.base
        self.buffer = b""

    def push(self, data: bytes) -> Pointer:
        self.allocation_pointer -= len(data)
        self.buffer = data + self.buffer
        return self.allocation_pointer

    def align(self, alignment=16) -> None:
        offset = int(self.allocation_pointer.near) % alignment
        self.push(bytes(offset))

    async def flush(self, transport: base.MemoryWriter) -> Pointer:
        await transport.write(self.allocation_pointer, self.buffer)
        self.buffer = b""
        return self.allocation_pointer

async def launch_futex_monitor(task: base.Task, transport: base.MemoryTransport, allocator: memory.AllocatorInterface,
                               process_resources: ProcessResources, monitor: ChildTaskMonitor,
                               futex_pointer: Pointer, futex_value: int) -> ChildTask:
    serializer = memsys.Serializer()
    # build the trampoline and push it on the stack
    stack_data = process_resources.build_trampoline_stack(process_resources.futex_helper_func, futex_pointer, futex_value)
    # TODO we need appropriate alignment here, we're just lucky because the alignment works fine by accident right now
    stack_pointer = serializer.serialize_data(stack_data)
    logger.info("about to serialize")
    async with serializer.with_flushed(transport, allocator):
        logger.info("did serialize")
        futex_task = await monitor.clone(
            task,
            lib.CLONE_VM|lib.CLONE_FILES|signal.SIGCHLD, stack_pointer.pointer,
            ctid=task.address_space.null(), newtls=task.address_space.null())
        # wait for futex helper to SIGSTOP itself,
        # which indicates the trampoline is done and we can deallocate the stack.
        event = await futex_task.wait_for_stop_or_exit()
        if event.died():
            raise Exception("thread internal futex-waiting task died unexpectedly", event)
        # resume the futex_task so it can start waiting on the futex
        await futex_task.send_signal(signal.SIGCONT)
    # the stack will be freed as it is no longer needed, but the futex pointer will live on
    return futex_task

class ThreadMaker:
    def __init__(self,
                 task: Task,
                 monitor: ChildTaskMonitor,
                 process_resources: ProcessResources) -> None:
        self.task = task
        self.monitor = monitor
        # TODO pull this function out of somewhere sensible
        self.process_resources = process_resources

    async def clone(self, flags: int, child_stack: Pointer, newtls: Pointer) -> Thread:
        """Provides an asynchronous interface to the CLONE_CHILD_CLEARTID functionality

        Executes the instruction "ret" immediately after cloning.

        """
        # the mapping is SHARED rather than PRIVATE so that the futex is shared even if CLONE_VM
        # unshares the address space
        # TODO not sure that actually works
        mapping = await far.mmap(self.task.base, 4096, memory.ProtFlag.READ|memory.ProtFlag.WRITE,
                                 memory.MapFlag.SHARED|memory.MapFlag.ANONYMOUS)
        futex_pointer = mapping.as_pointer()
        futex_task = await launch_futex_monitor(
            self.task.base, self.task.transport, self.task.allocator, self.process_resources, self.monitor,
            futex_pointer, 0)
        # the only part of the memory mapping that's being used now is the futex address, which is a
        # huge waste. oh well, later on we can allocate futex addresses out of a shared mapping.
        child_task = await self.monitor.clone(
            self.task.base,
            flags | lib.CLONE_CHILD_CLEARTID, child_stack,
            ctid=futex_pointer, newtls=newtls)
        return Thread(child_task, futex_task, handle.MemoryMapping(self.task.base, mapping))

    async def make_cthread(self, flags: int,
                          function: FunctionPointer, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0,
    ) -> CThread:
        # allocate memory for the stack
        stack_size = 4096
        mapping = await self.task.mmap(stack_size, memory.ProtFlag.READ|memory.ProtFlag.WRITE, memory.MapFlag.PRIVATE)
        stack = BufferedStack(mapping.pointer + stack_size)
        # build stack
        stack.push(self.process_resources.build_trampoline_stack(function, arg1, arg2, arg3, arg4, arg5, arg6))
        # copy the stack over
        stack_pointer = await stack.flush(self.task.transport)
        # TODO actually allocate TLS
        tls = self.task.address_space.null()
        thread = await self.clone(flags|signal.SIGCHLD, stack_pointer, tls)
        return CThread(thread, mapping)

class RsyscallConnection:
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 tofd: AsyncFileDescriptor[WritableFile],
                 fromfd: AsyncFileDescriptor[ReadableFile],
    ) -> None:
        self.tofd = tofd
        self.fromfd = fromfd
        self.buffer = ReadBuffer()

    async def close(self) -> None:
        await self.tofd.aclose()
        await self.fromfd.aclose()

    async def write_request(self, number: int,
                            arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> None:
        request = ffi.new('struct rsyscall_syscall*',
                          (number, (arg1, arg2, arg3, arg4, arg5, arg6)))
        try:
            await self.tofd.write(bytes(ffi.buffer(request)))
        except OSError as e:
            # we raise a different exception so that users can distinguish syscall errors from
            # transport errors
            raise RsyscallException() from e

    async def read_response(self) -> int:
        size = ffi.sizeof('unsigned long')
        response_bytes = self.buffer.read_length(size)
        while response_bytes is None:
            new_data = await self.fromfd.read()
            if len(new_data) == 0:
                raise RsyscallHangup()
            self.buffer.feed_bytes(new_data)
            response_bytes = self.buffer.read_length(size)
        else:
            response, = struct.unpack('q', response_bytes)
            return response

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

class ReadBuffer:
    def __init__(self) -> None:
        self.buf = b""

    def feed_bytes(self, data: bytes) -> None:
        self.buf += data

    def read_length(self, length: int) -> t.Optional[bytes]:
        if length <= len(self.buf):
            section = self.buf[:length]
            self.buf = self.buf[length:]
            return section
        else:
            return None

class ChildConnection(base.SyscallInterface):
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 rsyscall_connection: RsyscallConnection,
                 server_task: ChildTask,
                 futex_task: t.Optional[ChildTask],
    ) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.server_task = server_task
        self.futex_task = futex_task
        self.identifier_process = self.server_task.process.near
        self.logger = logging.getLogger(f"rsyscall.ChildConnection.{int(self.server_task.process)}")
        self.infd: handle.FileDescriptor
        self.outfd: handle.FileDescriptor
        self.activity_fd: near.FileDescriptor
        self.request_lock = trio.Lock()
        self.pending_responses: t.List[SyscallResponse] = []
        self.running: trio.Event = None

    def store_remote_side_handles(self, infd: handle.FileDescriptor, outfd: handle.FileDescriptor) -> None:
        # these are needed so that we don't close them with garbage collection
        self.infd = infd
        self.outfd = outfd
        # this is part of the SyscallInterface
        self.activity_fd = infd.near

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def _read_syscall_response(self) -> int:
        response: int
        async with trio.open_nursery() as nursery:
            async def read_response() -> None:
                nonlocal response
                response = await self.rsyscall_connection.read_response()
                raise_if_error(response)
                nursery.cancel_scope.cancel()
            async def server_exit() -> None:
                # meaning the server exited
                await self.server_task.wait_for_exit()
                raise ChildExit()
            async def futex_exit() -> None:
                if self.futex_task is not None:
                    # meaning the server called exec or exited; we don't
                    # wait to see which one.
                    await self.futex_task.wait_for_exit()
                    raise MMRelease()
            nursery.start_soon(read_response)
            nursery.start_soon(server_exit)
            nursery.start_soon(futex_exit)
        return response

    async def _process_response_for(self, response: SyscallResponse) -> None:
        try:
            ret = await self._read_syscall_response()
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
            with trio.open_cancel_scope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

class RsyscallInterface(base.SyscallInterface):
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
                 infd: far.FileDescriptor, outfd: far.FileDescriptor) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.logger = logging.getLogger(f"rsyscall.RsyscallConnection.{identifier_process.id}")
        self.identifier_process = identifier_process
        self.activity_fd = infd.near
        # these are needed so that we don't accidentally close them when doing a do_cloexec_except
        self.infd = infd
        self.outfd = outfd
        self.request_lock = trio.Lock()
        self.pending_responses: t.List[SyscallResponse] = []
        self.running: trio.Event = None

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
            with trio.open_cancel_scope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

async def call_function(task: Task, stack: BufferedStack, process_resources: ProcessResources,
                        function: FunctionPointer, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> ChildEvent:
    "Calls a C function and waits for it to complete. Returns the ChildEvent that the child thread terminated with."
    stack.align()
    stack.push(process_resources.build_trampoline_stack(function, arg1, arg2, arg3, arg4, arg5, arg6))
    stack_pointer = await stack.flush(task.transport)
    # we directly spawn a thread for the function and wait on it
    pid = await raw_syscall.clone(task.syscall, lib.CLONE_VM|lib.CLONE_FILES, stack_pointer, ptid=None, ctid=None, newtls=None)
    process = base.Process(task.process_namespace, near.Process(pid))
    siginfo = await memsys.waitid(task.syscall, task.transport, task.allocator,
                                  process, lib._WALL|lib.WEXITED)
    struct = ffi.cast('siginfo_t*', ffi.from_buffer(siginfo))
    child_event = ChildEvent.make(ChildCode(struct.si_code),
                                  pid=int(struct.si_pid), uid=int(struct.si_uid),
                                  status=int(struct.si_status))
    return child_event

async def do_cloexec_except(task: Task, process_resources: ProcessResources,
                            excluded_fds: t.Iterable[near.FileDescriptor]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    stack_size = 4096
    async with (await task.mmap(stack_size, memory.ProtFlag.READ|memory.ProtFlag.WRITE, memory.MapFlag.PRIVATE)) as mapping:
        stack = BufferedStack(mapping.pointer + stack_size)
        fd_array = array.array('i', [int(fd) for fd in excluded_fds])
        fd_array_ptr = stack.push(fd_array.tobytes())
        child_event = await call_function(task, stack, process_resources,
                                          process_resources.do_cloexec_func, fd_array_ptr, len(fd_array))
        if not child_event.clean():
            raise Exception("cloexec function child died!", child_event)

async def unshare_files(
        task: Task, monitor: ChildTaskMonitor, process_resources: ProcessResources,
        close_in_old_space: t.List[near.FileDescriptor],
        copy_to_new_space: t.List[near.FileDescriptor],
        going_to_exec: bool,
) -> None:
    serializer = memsys.Serializer()
    fds_ptr = serializer.serialize_data(array.array('i', [int(fd) for fd in close_in_old_space]).tobytes())
    stack_ptr = serializer.serialize_lambda(trampoline_stack_size,
        lambda: process_resources.build_trampoline_stack(process_resources.stop_then_close_func,
                                                         fds_ptr.pointer, len(close_in_old_space)),
                                            # aligned for the stack
                                            alignment=16)
    async with serializer.with_flushed(task.transport, task.allocator):
        closer_task = await monitor.clone(
            task.base,
            lib.CLONE_VM|lib.CLONE_FS|lib.CLONE_FILES|lib.CLONE_IO|lib.CLONE_SIGHAND|lib.CLONE_SYSVSEM|signal.SIGCHLD,
            stack_ptr.pointer,
            ctid=task.address_space.null(), newtls=task.address_space.null())
        event = await closer_task.wait_for_stop_or_exit()
        if event.died():
            raise Exception("stop_then_close task died unexpectedly", event)
        # perform the actual unshare
        await near.unshare(task.base.sysif, near.UnshareFlag.FILES)
        # tell the closer task to close
        await closer_task.send_signal(signal.SIGCONT)
        await closer_task.wait_for_exit()
    # perform a cloexec
    if not going_to_exec:
        await do_cloexec_except(task, process_resources, copy_to_new_space)

def merge_adjacent_writes(write_ops: t.List[t.Tuple[Pointer, bytes]]) -> t.List[t.Tuple[Pointer, bytes]]:
    "Note that this is only effective inasmuch as the list is sorted."
    if len(write_ops) == 0:
        return []
    write_ops = sorted(write_ops, key=lambda op: int(op[0]))
    outputs: t.List[t.Tuple[Pointer, bytes]] = []
    last_pointer, last_data = write_ops[0]
    for pointer, data in write_ops[1:]:
        if int(last_pointer + len(last_data)) == int(pointer):
            last_data += data
        elif int(last_pointer + len(last_data)) > int(pointer):
            raise Exception("pointers passed to memcpy are overlapping!")
        else:
            outputs.append((last_pointer, last_data))
            last_pointer, last_data = pointer, data
    outputs.append((last_pointer, last_data))
    return outputs

def merge_adjacent_reads(read_ops: t.List[t.Tuple[Pointer, int]]) -> t.List[t.Tuple[Pointer, int]]:
    "Note that this is only effective inasmuch as the list is sorted."
    if len(read_ops) == 0:
        return []
    read_ops = sorted(read_ops, key=lambda op: int(op[0]))
    outputs: t.List[t.Tuple[Pointer, int]] = []
    last_pointer, last_size = read_ops[0]
    for pointer, size in read_ops[1:]:
        if int(last_pointer + last_size) == int(pointer):
            last_size += size
        elif int(last_pointer + last_size) > int(pointer):
            raise Exception("pointers passed to memcpy are overlapping!")
        else:
            outputs.append((last_pointer, last_size))
            last_pointer, last_size = pointer, size
    outputs.append((last_pointer, last_size))
    return outputs

class LocalMemoryTransport(base.MemoryTransport):
    "This is a memory transport that only works on local pointers."
    def inherit(self, task: handle.Task) -> LocalMemoryTransport:
        return self

    async def write(self, dest: Pointer, data: bytes) -> None:
        await self.batch_write([(dest, data)])

    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        for dest, data in ops:
            src = base.to_local_pointer(data)
            n = len(data)
            base.memcpy(dest, src, n)

    async def read(self, src: Pointer, n: int) -> bytes:
        [data] = await self.batch_read([(src, n)])
        return data

    async def batch_read(self, ops: t.List[t.Tuple[Pointer, int]]) -> t.List[bytes]:
        ret: t.List[bytes] = []
        for src, n in ops:
            buf = bytearray(n)
            dest = base.to_local_pointer(buf)
            base.memcpy(dest, src, n)
            ret.append(bytes(buf))
        return ret

@dataclass
class SocketMemoryTransport(base.MemoryTransport):
    """This class wraps a pair of connected file descriptors, one of which is in the local address space.

    The task owning the "local" file descriptor is guaranteed to be in the local address space. This
    means Python runtime memory, such as bytes objects, can be written to it without fear.  The
    "remote" file descriptor is somewhere else - possibly in the same task, possibly on some other
    system halfway across the planet.

    This pair can be used through the helper methods on this class, or borrowed for direct use. When
    directly used, care must be taken to ensure that at the end of use, the buffer between the pair
    is empty; otherwise later users will get that stray leftover data when they try to use it.

    """
    local: AsyncFileDescriptor[ReadableWritableFile]
    remote: handle.FileDescriptor
    lock: trio.Lock

    @property
    def remote_is_local(self) -> bool:
        return self.remote.task.address_space == base.local_address_space

    def inherit(self, task: handle.Task) -> SocketMemoryTransport:
        return SocketMemoryTransport(self.local, task.make_fd_handle(self.remote), self.lock)

    async def _unlocked_single_write(self, dest: Pointer, data: bytes) -> None:
        src = base.to_local_pointer(data)
        n = len(data)
        if self.remote_is_local:
            base.memcpy(dest, src, n)
            return
        rtask = self.remote.task
        near_read_fd = self.remote.near
        near_dest = rtask.to_near_pointer(dest)
        wtask = self.local.underlying.task.base
        near_write_fd = self.local.underlying.handle.near
        near_src = wtask.to_near_pointer(src)
        async def read() -> None:
            i = 0
            while (n - i) > 0:
                ret = await near.read(rtask.sysif, near_read_fd, near_dest+i, n-i)
                i += ret
        async def write() -> None:
            i = 0
            while (n - i) > 0:
                ret = await self.local.write_raw(wtask.sysif, near_write_fd, near_src+i, n-i)
                i += ret
        async with trio.open_nursery() as nursery:
            nursery.start_soon(read)
            nursery.start_soon(write)

    async def _unlocked_batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        ops = sorted(ops, key=lambda op: int(op[0]))
        ops = merge_adjacent_writes(ops)
        if len(ops) <= 1:
            [(dest, data)] = ops
            await self._unlocked_single_write(dest, data)
        else:
            # TODO use an iovec
            # build the full iovec at the start
            # write it over with unlocked_single_write
            # call readv
            # on partial read, fall back to unlocked_single_write for the rest of that section,
            # then go back to an incremented iovec
            for dest, data in ops:
                await self._unlocked_single_write(dest, data)

    async def write(self, dest: Pointer, data: bytes) -> None:
        await self.batch_write([(dest, data)])

    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        async with self.lock:
            await self._unlocked_batch_write(ops)

    async def _unlocked_single_read(self, src: Pointer, n: int) -> bytes:
        buf = bytearray(n)
        dest = base.to_local_pointer(buf)
        if self.remote_is_local:
            base.memcpy(dest, src, n)
            return bytes(buf)
        rtask = self.local.underlying.task.base
        near_dest = rtask.to_near_pointer(dest)
        near_read_fd = self.local.underlying.handle.near
        wtask = self.remote.task
        near_src = wtask.to_near_pointer(src)
        near_write_fd = self.remote.near
        async def read() -> None:
            i = 0
            while (n - i) > 0:
                ret = await self.local.read_raw(rtask.sysif, near_read_fd, near_dest+i, n-i)
                i += ret
        async def write() -> None:
            i = 0
            while (n - i) > 0:
                ret = await near.write(wtask.sysif, near_write_fd, near_src+i, n-i)
                i += ret
        async with trio.open_nursery() as nursery:
            nursery.start_soon(read)
            nursery.start_soon(write)
        return bytes(buf)

    async def _unlocked_batch_read(self, ops: t.List[t.Tuple[Pointer, int]]) -> t.List[bytes]:
        ops = merge_adjacent_reads(ops)
        ret: t.List[bytes] = []
        for src, size in ops:
            ret.append(await self._unlocked_single_read(src, size))
        return ret

    async def read(self, src: Pointer, n: int) -> bytes:
        [data] = await self.batch_read([(src, n)])
        return data

    async def batch_read(self, ops: t.List[t.Tuple[Pointer, int]]) -> t.List[bytes]:
        async with self.lock:
            return (await self._unlocked_batch_read(ops))


class AsyncReadBuffer:
    def __init__(self, fd: AsyncFileDescriptor[ReadableFile]) -> None:
        self.fd = fd
        self.buf = b""

    async def _read(self) -> t.Optional[bytes]:
        data = await self.fd.read()
        if len(data) == 0:
            if len(self.buf) != 0:
                raise Exception("got EOF while we still hold unhandled buffered data")
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

    async def read_netstring(self) -> t.Optional[bytes]:
        length_bytes = await self.read_until_delimiter(b':')
        if length_bytes is None:
            return None
        length = int(length_bytes)
        data = await self.read_length(length)
        if data is None:
            raise Exception("hangup before netstring data")
        comma = await self.read_length(1)        
        if comma is None:
            raise Exception("hangup before comma at end of netstring")
        if comma != b",":
            raise Exception("bad netstring delimiter", comma)
        return data

async def read_lines(fd: AsyncFileDescriptor[ReadableFile]) -> t.AsyncIterator[bytes]:
    buf = b""
    while True:
        # invariant: buf contains no newlines
        data = await fd.read()
        if len(data) == 0:
            # yield up whatever's left
            print("got EOF while reading lines")
            if len(buf) != 0:
                yield buf
            break
        buf += data
        # buf may contain newlines, yield up the lines
        while True:
            try:
                i = buf.index(b"\n")
            except ValueError:
                break
            else:
                line = buf[:i]
                print("read line", line)
                yield line
                buf = buf[i+1:]

async def set_singleton_robust_futex(task: far.Task, transport: base.MemoryTransport, allocator: memory.PreallocatedAllocator,
                                     futex_value: int,
) -> Pointer:
    serializer = memsys.Serializer()
    futex_offset = ffi.sizeof('struct robust_list')
    futex_data = struct.pack('=I', futex_value)
    robust_list_entry = serializer.serialize_lambda(
        futex_offset + len(futex_data),
        # we indicate that this is the last entry in the list by pointing it to itself
        lambda: (bytes(ffi.buffer(ffi.new('struct robust_list*', (ffi.cast('void*', robust_list_entry.pointer),))))
                 + futex_data))
    robust_list_head = serializer.serialize_cffi(
        'struct robust_list_head', lambda:
        ((ffi.cast('void*', robust_list_entry.pointer),), futex_offset, ffi.cast('void*', 0)))
    async with serializer.with_flushed(transport, allocator):
        await far.set_robust_list(task, robust_list_head.pointer, robust_list_head.size)
    futex_pointer = robust_list_entry.pointer + futex_offset
    return futex_pointer

async def make_connections(access_task: Task,
                           # regrettably asymmetric...
                           # it would be nice to unify connect/accept with passing file descriptors somehow.
                           access_connection: t.Optional[t.Tuple[Path, FileDescriptor[UnixSocketFile]]],
                           connecting_task: Task,
                           connecting_connection: t.Tuple[handle.FileDescriptor, handle.FileDescriptor],
                           parent_task: Task,
                           count: int) -> t.List[t.Tuple[FileDescriptor[ReadableWritableFile], handle.FileDescriptor]]:
    # so there's 1. the access task, through which we access the syscall and data fds,
    # 2. the parent task, and
    # 3. the connection between the access and parent task, so that we can have the parent task pass down the fds,
    # while the access task uses them.
    # okay but this is a slight simplification, because there may also be,
    # 4. the connection task, which is a task that actually gets the fds and passes them down to the parent task
    access_socks: t.List[FileDescriptor[ReadableWritableFile]] = []
    connecting_socks: t.List[FileDescriptor[ReadableWritableFile]] = []
    if access_task.base.fd_table == connecting_task.base.fd_table:
        async def make_conn() -> t.Tuple[FileDescriptor[ReadableWritableFile], FileDescriptor[ReadableWritableFile]]:
            return (await access_task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0))
    else:
        if access_connection is not None:
            access_connection_path, access_connection_socket = access_connection
        else:
            raise Exception("must pass access connection when access task and connecting task are different")
        async def make_conn() -> t.Tuple[FileDescriptor[ReadableWritableFile], FileDescriptor[ReadableWritableFile]]:
            left_sock = await access_task.socket_unix(socket.SOCK_STREAM)
            await robust_unix_connect(access_connection_path, left_sock)
            right_sock: FileDescriptor[UnixSocketFile]
            right_sock, _ = await access_connection_socket.accept(os.O_CLOEXEC) # type: ignore
            return left_sock, right_sock
    for _ in range(count):
        access_sock, connecting_sock = await make_conn()
        access_socks.append(access_sock)
        connecting_socks.append(connecting_sock)
    passed_socks: t.List[handle.FileDescriptor]
    if connecting_task.base.fd_table == parent_task.base.fd_table:
        passed_socks = []
        for sock in connecting_socks:
            passed_socks.append(parent_task.base.make_fd_handle(sock.handle))
            await sock.handle.invalidate()
    else:
        assert connecting_connection is not None
        await memsys.sendmsg_fds(connecting_task.base, connecting_task.transport, connecting_task.allocator,
                                 connecting_connection[0].far, [sock.handle.far for sock in connecting_socks])
        near_passed_socks = await memsys.recvmsg_fds(parent_task.base, parent_task.transport, parent_task.allocator,
                                                     connecting_connection[1].far, count)
        passed_socks = [parent_task.base.make_fd_handle(sock) for sock in near_passed_socks]
        # don't need these in the connecting task anymore
        for sock in connecting_socks:
            await sock.aclose()
    return list(zip(access_socks, passed_socks))

async def spawn_rsyscall_thread(
        access_sock: AsyncFileDescriptor[ReadableWritableFile],
        remote_sock: handle.FileDescriptor,
        parent_task: Task, thread_maker: ThreadMaker, function: FunctionPointer,
    ) -> t.Tuple[Task, CThread]:
    cthread = await thread_maker.make_cthread(
        lib.CLONE_VM|lib.CLONE_FS|lib.CLONE_FILES|lib.CLONE_IO|lib.CLONE_SIGHAND|lib.CLONE_SYSVSEM|signal.SIGCHLD,
        function, remote_sock.near, remote_sock.near)
    syscall = ChildConnection(
        RsyscallConnection(access_sock, access_sock),
        cthread.child_task,
        cthread.futex_task)
    new_base_task = base.Task(syscall, parent_task.fd_table, parent_task.address_space, parent_task.base.fs)
    remote_sock_handle = new_base_task.make_fd_handle(remote_sock)
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    new_task = Task(new_base_task,
                    parent_task.transport.inherit(new_base_task),
                    parent_task.allocator.inherit(new_base_task),
                    parent_task.sigmask.inherit(),
                    parent_task.process_namespace)
    return new_task, cthread

async def rsyscall_exec(
        parent_stdtask: StandardTask,
        rsyscall_thread: RsyscallThread,
        rsyscall_server_path: handle.Path,
    ) -> None:
    "Exec into the standalone rsyscall_server executable"
    stdtask = rsyscall_thread.stdtask
    [(async_access_describe_sock, passed_describe_sock)] = await stdtask.make_async_connections(1)
    # create this guy and pass him down to the new thread
    futex_memfd = await memsys.memfd_create(stdtask.task.base, stdtask.task.transport, stdtask.task.allocator,
                                                  b"child_robust_futex_list", lib.MFD_CLOEXEC)
    child_futex_memfd = stdtask.task.base.make_fd_handle(futex_memfd)
    parent_futex_memfd = parent_stdtask.task.base.make_fd_handle(futex_memfd)
    syscall: ChildConnection = stdtask.task.base.sysif # type: ignore
    def encode(fd: near.FileDescriptor) -> bytes:
        return str(int(fd)).encode()
    async def do_unshare(close_in_old_space: t.List[near.FileDescriptor],
                         copy_to_new_space: t.List[near.FileDescriptor]) -> None:
        # unset cloexec on all the fds we want to copy to the new space
        for copying_fd in copy_to_new_space:
            await near.fcntl(syscall, copying_fd, fcntl.F_SETFD, 0)
        child_task = await rsyscall_thread.execve(
            rsyscall_server_path, [
                b"rsyscall_server",
                encode(passed_describe_sock.near), encode(syscall.infd.near), encode(syscall.outfd.near),
                *[encode(fd) for fd in copy_to_new_space],
            ], {}, [stdtask.child_monitor.signal_queue.signal_block])
        # the futex task we used before is dead now that we've exec'd, have
        # to null it out
        syscall.futex_task = None
        # TODO maybe remove dependence on parent task for closing?
        for fd in close_in_old_space:
            await near.close(parent_stdtask.task.base.sysif, fd)
        stdtask.task.base.address_space = base.AddressSpace(rsyscall_thread.thread.child_task.process.near.id)
        # we mutate the allocator instead of replacing to so that anything that
        # has stored the allocator continues to work
        stdtask.task.allocator.allocator = memory.Allocator(stdtask.task.base)
        print("allocators")
        print("base", stdtask.task.base)
        print("allocator task", stdtask.task.allocator.task)
    await stdtask.task.base.unshare_files(do_unshare)

    #### read symbols from describe fd
    symbols: t.Dict[bytes, far.Pointer] = {}
    async for line in read_lines(async_access_describe_sock):
        key, value = line.rstrip().split(b'=', 1)
        symbols[key] = far.Pointer(stdtask.task.base.address_space, near.Pointer(int(value, 16)))
    await async_access_describe_sock.aclose()
    stdtask.process = ProcessResources.make_from_symbols(symbols)

    #### make new futex task
    # resize memfd appropriately
    futex_memfd_size = 4096
    await parent_futex_memfd.ftruncate(futex_memfd_size)
    # set up local mapping
    local_mapping = await parent_futex_memfd.mmap(
        futex_memfd_size, memory.ProtFlag.READ|memory.ProtFlag.WRITE, memory.MapFlag.SHARED)
    await parent_futex_memfd.invalidate()
    local_mapping_pointer = local_mapping.as_pointer()
    # set up remote mapping
    remote_mapping = await child_futex_memfd.mmap(
        futex_memfd_size, memory.ProtFlag.READ|memory.ProtFlag.WRITE, memory.MapFlag.SHARED)
    await child_futex_memfd.invalidate()
    remote_mapping_pointer = remote_mapping.as_pointer()

    # have to set the futex pointer to this nonsense or the kernel won't wake on it properly
    futex_value = lib.FUTEX_WAITERS|(int(rsyscall_thread.thread.child_task.process) & lib.FUTEX_TID_MASK)
    # this is distasteful and leaky, we're relying on the fact that the PreallocatedAllocator never frees things
    remote_futex_pointer = await set_singleton_robust_futex(
        stdtask.task.base, stdtask.task.transport,
        memory.PreallocatedAllocator(remote_mapping_pointer, futex_memfd_size), futex_value)
    local_futex_pointer = local_mapping_pointer + (int(remote_futex_pointer) - int(remote_mapping_pointer))
    # now we start the futex monitor
    futex_task = await launch_futex_monitor(parent_stdtask.task.base, parent_stdtask.task.transport,
                                            parent_stdtask.task.allocator,
                                            parent_stdtask.process, parent_stdtask.child_monitor,
                                            local_futex_pointer, futex_value)
    syscall.futex_task = futex_task
    # TODO how do we unmap the remote mapping?
    rsyscall_thread.thread = Thread(rsyscall_thread.thread.child_task, futex_task,
                                    handle.MemoryMapping(parent_stdtask.task.base, local_mapping))

# Need to identify the host, I guess
# I shouldn't abstract this too much - I should just use ssh.
@contextlib.asynccontextmanager
async def run_socket_binder(
        task: StandardTask,
        ssh_command: SSHCommand,
) -> t.AsyncGenerator[bytes, None]:
    stdout_pipe = await task.task.pipe()
    async_stdout = await AsyncFileDescriptor.make(task.epoller, stdout_pipe.rfd)
    # TODO I should have this process set PDEATHSIG so that even if we hard crash, it will exit too
    thread = await task.fork()
    bootstrap_executable = await thread.stdtask.task.open(thread.stdtask.filesystem.rsyscall_bootstrap_path, os.O_RDONLY)
    stdout = thread.stdtask.task.base.make_fd_handle(stdout_pipe.wfd.handle)
    await stdout_pipe.wfd.handle.invalidate()
    await thread.stdtask.unshare_files()
    # TODO we are relying here on the fact that replace_with doesn't set cloexec on the new fd.
    # maybe we should explicitly list what we want to pass down...
    # or no, let's tag things as inheritable, maybe?
    await thread.stdtask.stdout.replace_with(stdout)
    await thread.stdtask.stdin.replace_with(bootstrap_executable)
    async with thread:
        child = await ssh_command.args([ssh_bootstrap_script_contents]).exec(thread)
        # from... local?
        # I guess this throws into sharper relief the distinction between core and module.
        # The ssh bootstrapping stuff should come from a different class,
        # which hardcodes the path,
        # and which works only for local tasks.
        # So in the meantime we'll continue to get it from task.filesystem.

        # sigh, openssh doesn't close its local stdout when it sees HUP/EOF on
        # the remote stdout. so we can't use EOF to signal end of our lines, and
        # instead have to have a sentinel to tell us when to stop reading.
        lines_aiter = read_lines(async_stdout)
        tmp_path_bytes = await lines_aiter.__anext__()
        done = await lines_aiter.__anext__()
        if done != b"done":
            raise Exception("socket binder violated protocol, got instead of done:", done)
        await async_stdout.aclose()
        logger.info("socket bootstrap done, got tmp path %s", tmp_path_bytes)
        yield tmp_path_bytes
        (await child.wait_for_exit()).check()

async def ssh_bootstrap(
        parent_task: StandardTask,
        ssh_command: SSHCommand,
        # the local path we'll use for the socket
        local_socket_path: handle.Path,
        # the directory we're bootstrapping out of
        tmp_path_bytes: bytes,
) -> t.Tuple[ChildTask, StandardTask]:
    # identify local path
    task = parent_task.task
    local_data_path = Path(task, local_socket_path)
    # start bootstrap and forward local socket
    bootstrap_thread = await parent_task.fork()
    bootstrap_child_task = await ssh_command.local_forward(
        str(local_socket_path), (tmp_path_bytes + b"/data").decode(),
    ).args([f"cd {tmp_path_bytes.decode()}; ./bootstrap rsyscall"]).exec(bootstrap_thread)
    # TODO should unlink the bootstrap after I'm done execing.
    # it would be better if sh supported fexecve, then I could unlink it before I exec...
    # TODO TODO this is dumb! waiting for the ssh forwarding to be established!
    # Oh, I guess we could... um...
    # We could have a third ssh command, just for the forwarding, which just echos something when done.
    # I feel that I'm forced into doing that, yeah.
    # Either that or we can do it with the other bootstrap. The socket bootstrap.
    # If we can somehow set up the forwarding after startup...
    # Urgh, we can't send the escape character since we're sending binary data over stdin.
    # Meh, let's continue.
    await trio.sleep(.1)
    # Connect to local socket 4 times
    async def make_async_connection() -> AsyncFileDescriptor[UnixSocketFile]:
        sock = await task.socket_unix(socket.SOCK_STREAM)
        await robust_unix_connect(local_data_path, sock)
        return (await AsyncFileDescriptor.make(parent_task.epoller, sock))
    async_bootstrap_describe_sock = await make_async_connection()
    async_describe_sock = await make_async_connection()
    async_local_syscall_sock = await make_async_connection()
    async_local_data_sock = await make_async_connection()
    # Read description off of bootstrap_describe
    bootstrap_describe_buf = AsyncReadBuffer(async_bootstrap_describe_sock)
    async def read_keyval(expected_key: bytes) -> bytes:
        keyval = await bootstrap_describe_buf.read_line()
        if keyval is None:
            raise Exception("expected key", expected_key, "got EOF instead")
        key, val = keyval.split(b"=", 1)
        if key != expected_key:
            raise Exception("expected key", expected_key, "got", key)
        return val
    # we use the pid of the local ssh process as our human-facing namespace identifier, since it is
    # more likely to be unique, and we already have it available.
    identifier_process = bootstrap_child_task.process
    identifier_pid = int(identifier_process)
    new_fd_table = far.FDTable(identifier_pid)
    async def read_fd(key: bytes) -> far.FileDescriptor:
        return far.FileDescriptor(new_fd_table, near.FileDescriptor(int(await read_keyval(key))))
    listening_fd = await read_fd(b"listening_sock")
    remote_syscall_fd = await read_fd(b"syscall_sock")
    remote_data_fd = await read_fd(b"data_sock")
    environ_tag = await bootstrap_describe_buf.read_line()
    if environ_tag != b"environ":
        raise Exception("expected to start reading the environment, instead got", environ_tag)
    print("HELLO reading environ now", remote_syscall_fd, remote_data_fd)
    environ: t.Dict[bytes, bytes] = {}
    while True:
        environ_elem = await bootstrap_describe_buf.read_netstring()
        if environ_elem is None:
            break
        # if someone passes us a malformed environment element without =, we'll just break, whatever
        key, val = environ_elem.split(b"=", 1)
        environ[key] = val
    await async_bootstrap_describe_sock.aclose()
    # Read even more description off of describe
    new_address_space = far.AddressSpace(identifier_pid)
    symbols: t.Dict[bytes, far.Pointer] = {}
    async for line in read_lines(async_describe_sock):
        key, value = line.rstrip().split(b'=', 1)
        symbols[key] = far.Pointer(new_address_space, near.Pointer(int(value, 16)))
    await async_describe_sock.aclose()
    # Build the new task!
    new_syscall = RsyscallInterface(RsyscallConnection(async_local_syscall_sock, async_local_syscall_sock),
                                    identifier_process.near, remote_syscall_fd, remote_syscall_fd)
    new_fs_information = far.FSInformation(identifier_pid, root=near.DirectoryFile(), cwd=near.DirectoryFile())
    new_base_task = base.Task(new_syscall, new_fd_table, new_address_space, new_fs_information)
    handle_remote_data_fd = new_base_task.make_fd_handle(remote_data_fd)
    new_transport = SocketMemoryTransport(async_local_data_sock, handle_remote_data_fd, trio.Lock())
    new_process_namespace = far.ProcessNamespace(identifier_pid)
    new_task = Task(new_base_task, new_transport,
                    memory.AllocatorClient.make_allocator(new_base_task),
                    # we assume ssh zeroes the sigmask before starting us
                    SignalMask(set()),
                    new_process_namespace)
    left_connecting_connection, right_connecting_connection = await new_task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    connecting_connection = (left_connecting_connection.handle, right_connecting_connection.handle)
    epoller = await new_task.make_epoll_center()
    child_monitor = await ChildTaskMonitor.make(new_task, epoller)
    new_stdtask = StandardTask(
        access_task=parent_task.task,
        access_epoller=parent_task.epoller,
        access_connection=(local_data_path, new_task.make_fd(listening_fd.near, UnixSocketFile())),
        connecting_task=new_task, connecting_connection=connecting_connection,
        task=new_task,
        process_resources=ProcessResources.make_from_symbols(symbols),
        filesystem_resources=FilesystemResources.make_from_environ(new_base_task, environ),
        epoller=epoller,
        child_monitor=child_monitor,
        local_epoller=epoller,
        environment=environ,
        stdin=new_task._make_fd(0, ReadableFile(shared=True)),
        stdout=new_task._make_fd(1, WritableFile(shared=True)),
        stderr=new_task._make_fd(2, WritableFile(shared=True)),
    )
    return bootstrap_child_task, new_stdtask

async def spawn_ssh(
        task: StandardTask, ssh_command: SSHCommand,
        local_socket_path: t.Optional[handle.Path]=None,
) -> t.Tuple[ChildTask, StandardTask]:
    # we could get rid of the need to touch the local filesystem by directly
    # speaking the openssh multiplexer protocol. or directly speaking the ssh
    # protocol for that matter.
    if local_socket_path is None:
        # we guess that the last argument of ssh command is the hostname. it
        # doesn't matter if it isn't, this is just for human-readability.
        guessed_hostname = ssh_command.arguments[-1]
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = (guessed_hostname+random_suffix+".sock").encode()
        path: handle.Path = task.filesystem.tmpdir/name
        local_socket_path = path
    socket_binder_path = b"/" + b"/".join(task.filesystem.socket_binder_path.components)
    async with run_socket_binder(task, ssh_command) as tmp_path_bytes:
        return (await ssh_bootstrap(task, ssh_command, local_socket_path, tmp_path_bytes))


class RsyscallThread:
    def __init__(self,
                 stdtask: StandardTask,
                 thread: Thread,
    ) -> None:
        self.stdtask = stdtask
        self.thread = thread

    async def execve(self, path: handle.Path, argv: t.Sequence[t.Union[str, bytes, Path]],
                     env_updates: t.Mapping[str, t.Union[str, bytes, Path]]={},
                     inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> ChildTask:
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
        await self.stdtask.task.sigmask.setmask(self.stdtask.task, sigmask)
        envp: t.Dict[bytes, bytes] = {**self.stdtask.environment}
        for key in env_updates:
            envp[os.fsencode(key)] = await fspath(env_updates[key])
        raw_envp: t.List[bytes] = []
        for key_bytes, value in envp.items():
            raw_envp.append(b''.join([key_bytes, b'=', value]))
        task = self.stdtask.task
        return (await self.thread.execveat(task.base.sysif, task.transport, task.allocator,
                                           path, [await fspath(arg) for arg in argv],
                                           raw_envp, flags=0))

    async def close(self) -> None:
        await self.thread.close()
        await self.stdtask.task.close()

    async def __aenter__(self) -> StandardTask:
        return self.stdtask

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()

@dataclass
class Pipe:
    rfd: FileDescriptor[ReadableFile]
    wfd: FileDescriptor[WritableFile]

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
                 arguments: t.List[str],
                 env_updates: t.Mapping[str, str]) -> None:
        self.executable_path = executable_path
        self.arguments = arguments
        self.env_updates = env_updates

    def args(self: T_command, args: t.List[str]) -> T_command:
        return type(self)(self.executable_path,
                             self.arguments + args,
                             self.env_updates)

    def env(self: T_command, env_updates: t.Mapping[str, str]) -> T_command:
        return type(self)(self.executable_path,
                             self.arguments,
                             {**self.env_updates, **env_updates})

    def __str__(self) -> str:
        ret = ""
        for key, value in self.env_updates.items():
            ret += f"{key}={value} "
        ret += str(self.executable_path)
        # skip first argument
        for arg in self.arguments[1:]:
            ret += f" {arg}"
        return ret

    # hmm we actually need an rsyscallthread to properly exec
    # would be nice to call this just "Thread".
    # we should namespace the current "Thread" properly, so we can do that...
    async def exec(self, thread: RsyscallThread) -> ChildTask:
        return (await thread.execve(self.executable_path, self.arguments, self.env_updates))

T_ssh_command = t.TypeVar('T_ssh_command', bound="SSHCommand")
class SSHCommand(Command):
    def ssh_options(self, config: t.Mapping[str, str]) -> SSHCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", f"{key}={value}"]
        return self.args(option_list)

    def proxy_command(self, command: Command) -> SSHCommand:
        return self.ssh_options({'ProxyCommand': str(command)})

    def local_forward(self, local_socket: str, remote_socket: str) -> SSHCommand:
        return self.args(["-L", f"{local_socket}:{remote_socket}"])

    @classmethod
    def make(cls: t.Type[T_ssh_command], executable_path: handle.Path) -> T_ssh_command:
        return cls(executable_path, ["ssh"], {})

class SSHDCommand(Command):
    def sshd_options(self, config: t.Mapping[str, str]) -> SSHDCommand:
        option_list: t.List[str] = []
        for key, value in config.items():
            option_list += ["-o", f"{key}={value}"]
        return self.args(option_list)

    @classmethod
    def make(cls, executable_path: handle.Path) -> SSHDCommand:
        return cls(executable_path, ["sshd"], {})

local_stdtask: t.Any = None # type: ignore

async def build_local_stdtask(nursery) -> StandardTask:
    return (await StandardTask.make_local())

async def exec_cat(thread: RsyscallThread, cat: Command,
                   infd: handle.FileDescriptor, outfd: handle.FileDescriptor) -> ChildTask:
    stdin = thread.stdtask.task.base.make_fd_handle(infd)
    stdout = thread.stdtask.task.base.make_fd_handle(outfd)
    await thread.stdtask.unshare_files()
    await thread.stdtask.stdin.replace_with(stdin)
    await thread.stdtask.stdout.replace_with(stdout)
    child_task = await cat.exec(thread)
    return child_task

async def do_stuff(thread: RsyscallThread) -> None:
    await thread.unshare_user()
    await thread.unshare_mount()
    await thread.bind_mount(home/".var/nix", "/nix")
    thread.stdtask.environ['NIX_CONF_DIR'] = '/nix/etc/nix'
    # now I can run Nix commands. neat!
    # So... yeah, this works and is good.
    # Well... doesn't this have the issue of wiping out whatever I might want to use out of /nix?
    # I guess I have that anyway. Nbd!
    # Actually, I guess I could have some more specific path knowledge,
    # with knowledge of actual mount points.
    # Kind of the same thing as using pointers in memory mappings...
    stdin = thread.stdtask.task.base.make_fd_handle(infd)
    stdout = thread.stdtask.task.base.make_fd_handle(outfd)
    await thread.stdtask.unshare_files()
    await thread.stdtask.stdin.replace_with(stdin)
    await thread.stdtask.stdout.replace_with(stdout)
    child_task = await cat.exec(thread)
    return child_task
