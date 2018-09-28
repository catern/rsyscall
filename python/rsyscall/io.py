from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore

from rsyscall.epoll import EpollEvent, EpollEventMask
import rsyscall.epoll

from rsyscall.base import Pointer, RsyscallException, RsyscallHangup
from rsyscall.base import MemoryGateway, LocalMemoryGateway, to_local_pointer
from rsyscall.base import SyscallInterface
import rsyscall.base as base
from rsyscall.raw_syscalls import UnshareFlag, NsType, SigprocmaskHow
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory_abstracted_syscalls as memsys
import rsyscall.memory as memory

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

class IdType(enum.IntEnum):
    PID = lib.P_PID # Wait for the child whose process ID matches id.
    PGID = lib.P_PGID # Wait for any child whose process group ID matches id.
    ALL = lib.P_ALL # Wait for any child; id is ignored.

class EpollCtlOp(enum.IntEnum):
    ADD = lib.EPOLL_CTL_ADD
    MOD = lib.EPOLL_CTL_MOD
    DEL = lib.EPOLL_CTL_DEL

class ChildCode(enum.Enum):
    EXITED = lib.CLD_EXITED # child called _exit(2)
    KILLED = lib.CLD_KILLED # child killed by signal
    DUMPED = lib.CLD_DUMPED # child killed by signal, and dumped core
    STOPPED = lib.CLD_STOPPED # child stopped by signal
    TRAPPED = lib.CLD_TRAPPED # traced child has trapped
    CONTINUED = lib.CLD_CONTINUED # child continued by SIGCONT

class UncleanExit(Exception):
    pass

@dataclass
class ChildEvent:
    code: ChildCode
    pid: int
    uid: int
    exit_status: t.Optional[int]
    sig: t.Optional[signal.Signals]

    @staticmethod
    def make(code: ChildCode, pid: int, uid: int, status: int):
        if code is ChildCode.EXITED:
            return ChildEvent(code, pid, uid, status, None)
        else:
            return ChildEvent(code, pid, uid, None, signal.Signals(status))

    def died(self) -> bool:
        return self.code in [ChildCode.EXITED, ChildCode.KILLED, ChildCode.DUMPED]
    def clean(self) -> bool:
        return self.code == ChildCode.EXITED and self.exit_status == 0

    def check(self) -> None:
        if self.clean():
            return None
        else:
            raise UncleanExit(self)

    def killed_with(self) -> signal.Signals:
        """What signal was the child killed with?

        Throws if the child was not killed with a signal.

        """
        if not self.died():
            raise Exception("Child isn't dead")
        if self.sig is None:
            raise Exception("Child wasn't killed with a signal")
        return self.sig

async def direct_syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
    "Make a syscall directly in the current thread."
    args = (ffi.cast('long', arg1), ffi.cast('long', arg2), ffi.cast('long', arg3),
            ffi.cast('long', arg4), ffi.cast('long', arg5), ffi.cast('long', arg6),
            number)
    ret = lib.rsyscall_raw_syscall(*args)
    return ret

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
    other_activity_fd = None
    logger = logging.getLogger("rsyscall.LocalSyscall")
    async def close_interface(self) -> None:
        pass

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        ret = await direct_syscall(number,
                                   arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                                   arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        if ret < 0:
            err = -ret
            raise OSError(err, os.strerror(err))
        return ret

class FunctionPointer(Pointer):
    "A function pointer."
    pass

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
        old_mask = await memsys.rt_sigprocmask(syscall, task.gateway, task.allocator, SigprocmaskHow.BLOCK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync?")
        self.mask = self.mask.union(mask)

    async def unblock(self, task: 'Task', mask: t.Set[signal.Signals]) -> None:
        syscall = self._validate(task)
        old_mask = await memsys.rt_sigprocmask(syscall, task.gateway, task.allocator, SigprocmaskHow.UNBLOCK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync?")
        self.mask = self.mask - mask

    async def setmask(self, task: 'Task', mask: t.Set[signal.Signals]) -> None:
        syscall = self._validate(task)
        old_mask = await memsys.rt_sigprocmask(syscall, task.gateway, task.allocator, SigprocmaskHow.SETMASK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync?")
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

T_file = t.TypeVar('T_file', bound=File)
T_file_co = t.TypeVar('T_file_co', bound=File, covariant=True)

class Task:
    def __init__(self, syscall: SyscallInterface,
                 gateway: MemoryGateway,
                 fd_namespace: base.FDNamespace,
                 address_space: base.AddressSpace,
                 mount: base.MountNamespace,
                 fs: base.FSInformation,
                 sigmask: SignalMask,
                 process_namespace: base.ProcessNamespace,
    ) -> None:
        self.syscall = syscall
        self.gateway = gateway
        self.address_space = address_space
        # Being able to allocate memory is like having a stack.
        # we really need to be able to allocate memory to get anything done - namely, to call syscalls.
        self.allocator = memory.Allocator(syscall, address_space)
        self.fd_namespace = fd_namespace
        self.mount = mount
        self.fs = fs
        self.sigmask = sigmask
        self.process_namespace = process_namespace

    async def close(self):
        await self.syscall.close_interface()

    async def exit(self, status: int) -> None:
        await raw_syscall.exit(self.syscall, status)
        await self.close()

    async def execveat(self, path: Path,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> None:
        _validate_path_and_task_match(self, path.pure)
        await memsys.execveat(self.syscall, self.gateway, self.allocator, path.pure, argv, envp, flags)
        await self.close()

    async def chdir(self, path: 'Path') -> None:
        await memsys.chdir(self.syscall, self.gateway, self.allocator, path.pure)

    async def unshare_fs(self) -> None:
        # we want this to return something that we can use to chdir
        raise NotImplementedError

    def _make_fd(self, num: int, file: T_file) -> FileDescriptor[T_file]:
        return FileDescriptor(self, base.FileDescriptor(self.fd_namespace, num), file)

    async def pipe(self, flags=os.O_CLOEXEC) -> Pipe:
        r, w = await memsys.pipe(self.syscall, self.gateway, self.allocator, flags)
        return Pipe(self._make_fd(r, ReadableFile(shared=False)),
                    self._make_fd(w, WritableFile(shared=False)))

    async def epoll_create(self, flags=lib.EPOLL_CLOEXEC) -> FileDescriptor[EpollFile]:
        epfd = await raw_syscall.epoll_create(self.syscall, flags)
        return self._make_fd(epfd, EpollFile())

    async def socket_unix(self, type: socket.SocketKind, protocol: int=0) -> FileDescriptor[UnixSocketFile]:
        sockfd = await raw_syscall.socket(self.syscall, lib.AF_UNIX, type, protocol)
        return self._make_fd(sockfd, UnixSocketFile())

    async def socket_inet(self, type: socket.SocketKind, protocol: int=0) -> FileDescriptor[InetSocketFile]:
        sockfd = await raw_syscall.socket(self.syscall, lib.AF_INET, type, protocol)
        return self._make_fd(sockfd, InetSocketFile())

    async def signalfd_create(self, mask: t.Set[signal.Signals]) -> FileDescriptor[SignalFile]:
        sigfd = await memsys.signalfd(self.syscall, self.gateway, self.allocator, mask, os.O_CLOEXEC)
        return self._make_fd(sigfd, SignalFile(mask))

    async def mmap(self, length: int, prot: memory.ProtFlag, flags: memory.MapFlag) -> memory.AnonymousMapping:
        # currently doesn't support specifying an address, nor specifying a file descriptor
        return (await memory.AnonymousMapping.make(
            self.syscall, self.address_space, length, prot, flags))

    async def make_epoller(self) -> Epoller:
        epfd = await self.epoll_create()
        # TODO handle deallocating the epoll fd if later steps fail
        if self.syscall.other_activity_fd is not None:
            epoller = Epoller(epfd, None)
            other_activity_fd = self._make_fd(self.syscall.other_activity_fd, File())
            epolled_other_activity_fd = await epoller.register(other_activity_fd, events=EpollEventMask.make(in_=True))
        else:
            # TODO this is a pretty low-level detail, not sure where is the right place to do this
            async def wait_readable():
                logger.debug("wait_readable(%s)", epfd.pure.number)
                await trio.hazmat.wait_readable(epfd.pure.number)
            epoller = Epoller(epfd, wait_readable)
        return epoller
        

class ReadableFile(File):
    async def read(self, fd: 'FileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        return (await memsys.read(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, count))

class WritableFile(File):
    async def write(self, fd: 'FileDescriptor[WritableFile]', buf: bytes) -> int:
        return (await memsys.write(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, buf))

class SeekableFile(File):
    async def lseek(self, fd: 'FileDescriptor[SeekableFile]', offset: int, whence: int) -> int:
        return (await raw_syscall.lseek(fd.task.syscall, fd.pure, offset, whence))

class ReadableWritableFile(ReadableFile, WritableFile):
    pass

class SignalFile(ReadableFile):
    def __init__(self, mask: t.Set[signal.Signals], shared=False) -> None:
        super().__init__(shared=shared)
        self.mask = mask

    async def signalfd(self, fd: 'FileDescriptor[SignalFile]', mask: t.Set[signal.Signals]) -> None:
        await memsys.signalfd(fd.task.syscall, fd.task.gateway, fd.task.allocator, mask, 0, fd=fd.pure)
        self.mask = mask

class DirectoryFile(SeekableFile):
    def __init__(self, raw_path: base.Path) -> None:
        # this is a fallback if we need to serialize this dirfd out
        self.raw_path = raw_path

    async def getdents(self, fd: 'FileDescriptor[DirectoryFile]', count: int) -> t.List[Dirent]:
        data = await memsys.getdents64(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, count)
        return rsyscall.stat.getdents64_parse(data)

    def as_path(self, fd: FileDescriptor[DirectoryFile]) -> Path:
        return Path(fd.task, base.Path(base.DirfdPathBase(fd.pure), b"."))

T_addr = t.TypeVar('T_addr', bound='Address')
class Address:
    addrlen: int
    @classmethod
    @abc.abstractmethod
    def parse(cls: t.Type[T_addr], data: bytes) -> T_addr: ...
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...

class UnixAddress(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_un')
    path: bytes
    def __init__(self, path: bytes) -> None:
        self.path = path

    T = t.TypeVar('T', bound='UnixAddress')
    @classmethod
    def parse(cls: t.Type[T], data: bytes) -> T:
        header = ffi.sizeof('sa_family_t')
        buf = ffi.from_buffer(data)
        if len(data) < header:
            raise Exception("data too smalllll")
        struct = ffi.cast('struct sockaddr_un*', buf)
        if struct.sun_family != lib.AF_UNIX:
            raise Exception("sun_family must be", lib.AF_UNIX, "is instead", header.sun_family)
        if len(data) == header:
            # unnamed socket, name is empty
            length = 0
        elif struct.sun_path[0] == b'\0':
            # abstract socket, entire buffer is part of path
            length = len(data) - header
        else:
            # pathname socket, path is null-terminated
            length = lib.strlen(struct.sun_path)
        return cls(bytes(ffi.buffer(struct.sun_path, length)))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_un*', (lib.AF_UNIX, self.path))
        real_length = ffi.sizeof('sa_family_t') + len(self.path) + 1
        return bytes(ffi.buffer(addr))[:real_length]

    def __str__(self) -> str:
        return f"UnixAddress({self.path})"

class InetAddress(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_in')
    def __init__(self, port: int, addr: int) -> None:
        # these are in host byte order, of course
        self.port = port
        self.addr = addr

    T = t.TypeVar('T', bound='InetAddress')
    @classmethod
    def parse(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct sockaddr_in*', ffi.from_buffer(data))
        if struct.sin_family != lib.AF_INET:
            raise Exception("sin_family must be", lib.AF_INET, "is instead", struct.sin_family)
        return cls(socket.ntohs(struct.sin_port), socket.ntohl(struct.sin_addr.s_addr))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_in*', (lib.AF_INET, socket.htons(self.port), (socket.htonl(self.addr),)))
        return ffi.buffer(addr)

    def addr_as_string(self) -> str:
        "Returns the addr portion of this address in 127.0.0.1 form"
        return socket.inet_ntoa(struct.pack("!I", self.addr))

    def __str__(self) -> str:
        return f"InetAddress({self.addr_as_string()}:{self.port})"

class SocketFile(t.Generic[T_addr], ReadableWritableFile):
    address_type: t.Type[T_addr]

    async def bind(self, fd: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await memsys.bind(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, addr.to_bytes())

    async def listen(self, fd: 'FileDescriptor[SocketFile]', backlog: int) -> None:
        await raw_syscall.listen(fd.task.syscall, fd.pure, backlog)

    async def connect(self, fd: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await memsys.connect(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, addr.to_bytes())

    async def getsockname(self, fd: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        data = await memsys.getsockname(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, self.address_type.addrlen)
        return self.address_type.parse(data)

    async def getpeername(self, fd: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        data = await memsys.getpeername(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, self.address_type.addrlen)
        return self.address_type.parse(data)

    async def getsockopt(self, fd: 'FileDescriptor[SocketFile[T_addr]]', level: int, optname: int, optlen: int) -> bytes:
        return (await memsys.getsockopt(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, level, optname, optlen))

    async def setsockopt(self, fd: 'FileDescriptor[SocketFile[T_addr]]', level: int, optname: int, optval: bytes) -> None:
        return (await memsys.setsockopt(fd.task.syscall, fd.task.gateway, fd.task.allocator, fd.pure, level, optname, optval))

    async def accept(self, fd: 'FileDescriptor[SocketFile[T_addr]]', flags: int) -> t.Tuple['FileDescriptor[SocketFile[T_addr]]', T_addr]:
        fdnum, data = await memsys.accept(fd.task.syscall, fd.task.gateway, fd.task.allocator,
                                          fd.pure, self.address_type.addrlen, flags)
        addr = self.address_type.parse(data)
        fd = FileDescriptor(fd.task, base.FileDescriptor(fd.pure.fd_namespace, fdnum), type(self)())
        return fd, addr

class UnixSocketFile(SocketFile[UnixAddress]):
    address_type = UnixAddress

class InetSocketFile(SocketFile[InetAddress]):
    address_type = InetAddress

class FileDescriptor(t.Generic[T_file_co]):
    "A file descriptor, plus a task to access it from, plus the file object underlying the descriptor."
    task: Task
    pure: base.FileDescriptor
    file: T_file_co
    def __init__(self, task: Task, pure: base.FileDescriptor, file: T_file_co) -> None:
        self.task = task
        self.pure = pure
        self.file = file
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
            return self.__class__(self.task, self.pure, self.file)
        else:
            raise Exception("file descriptor already closed")

    async def dup2(self, target: 'FileDescriptor') -> 'FileDescriptor[T_file_co]':
        """Make a copy of this file descriptor at target.number

        """
        if self.pure.fd_namespace != target.pure.fd_namespace:
            raise Exception("two fds are not in the same FDNamespace")
        if self is target:
            return self
        await raw_syscall.dup2(self.task.syscall, self.pure, target.pure)
        target.open = False
        new_fd = self.task._make_fd(target.pure.number, self.file)
        # dup2 unsets cloexec on the new copy, so:
        self.file.shared = True
        return new_fd

    async def as_argument(self) -> int:
        # TODO unset cloexec
        await self.disable_cloexec()
        return self.pure.number

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

class EpolledFileDescriptor(t.Generic[T_file_co]):
    epoller: Epoller
    underlying: FileDescriptor[T_file_co]
    queue: trio.hazmat.UnboundedQueue
    def __init__(self, epoller: Epoller, underlying: FileDescriptor[T_file_co], queue: trio.hazmat.UnboundedQueue) -> None:
        self.epoller = epoller
        self.underlying = underlying
        self.queue = queue
        self.in_epollfd = True

    async def modify(self, events: EpollEventMask) -> None:
        await self.epoller.modify(self.underlying, EpollEvent(self.underlying.pure.number, events))

    async def wait(self) -> t.List[EpollEvent]:
        while True:
            try:
                return self.queue.get_batch_nowait()
            except trio.WouldBlock:
                await self.epoller.do_wait()

    async def aclose(self) -> None:
        if self.in_epollfd:
            await self.epoller.delete(self.underlying)
            self.in_epollfd = False
        await self.underlying.aclose()

    async def __aenter__(self) -> EpolledFileDescriptor[T_file_co]:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

class Epoller:
    def __init__(self, epfd: FileDescriptor[EpollFile], wait_readable: t.Optional[t.Callable[[], t.Awaitable[None]]]) -> None:
        self.epfd = epfd
        self.wait_readable = wait_readable
        self.remote_new = RemoteNew(epfd.task.allocator, epfd.task.gateway)
        self.fd_map: t.Dict[int, EpolledFileDescriptor] = {}
        self.running_wait: t.Optional[trio.Event] = None

    async def register(self, fd: FileDescriptor[T_file], events: EpollEventMask=None
    ) -> EpolledFileDescriptor:
        if events is None:
            events = EpollEventMask.make()
        fd = fd.release()
        queue = trio.hazmat.UnboundedQueue()
        wrapper = EpolledFileDescriptor(self, fd, queue)
        self.fd_map[fd.pure.number] = wrapper
        await self.add(fd, EpollEvent(fd.pure.number, events))
        return wrapper

    async def do_wait(self) -> None:
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait

            # yield away first
            await trio.sleep(0)
            if self.wait_readable is not None:
                received_events = await self.wait(maxevents=32, timeout=0)
                if len(received_events) == 0:
                    await self.wait_readable()
                    received_events = await self.wait(maxevents=32, timeout=-1)
            else:
                received_events = await self.wait(maxevents=32, timeout=-1)
            for event in received_events:
                queue = self.fd_map[event.data].queue
                queue.put_nowait(event.events)

            self.running_wait = None
            running_wait.set()

    async def wait(self, maxevents: int, timeout: int) -> t.List[EpollEvent]:
        bufsize = maxevents * EpollEvent.bytesize()
        localbuf = bytearray(bufsize)
        with await self.remote_new.memory_allocator.malloc(bufsize) as events_ptr:
            count = await self.epfd.wait(events_ptr, maxevents, timeout)
            await self.remote_new.memory_gateway.memcpy(
                to_local_pointer(localbuf), events_ptr, bufsize)
        ret: t.List[EpollEvent] = []
        cur = 0
        for _ in range(count):
            ret.append(EpollEvent.from_bytes(localbuf[cur:cur+EpollEvent.bytesize()]))
            cur += EpollEvent.bytesize()
        return ret

    async def add(self, fd: FileDescriptor, event: EpollEvent) -> None:
        with await self.remote_new.new(event.to_bytes()) as event_ptr:
            await self.epfd.add(fd, event_ptr)

    async def modify(self, fd: FileDescriptor, event: EpollEvent) -> None:
        with await self.remote_new.new(event.to_bytes()) as event_ptr:
            await self.epfd.modify(fd, event_ptr)

    async def delete(self, fd: FileDescriptor) -> None:
        await self.epfd.delete(fd)

    async def close(self) -> None:
        await self.epfd.aclose()

    async def __aenter__(self) -> 'Epoller':
        return self

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()


class AsyncFileDescriptor(t.Generic[T_file_co]):
    epolled: EpolledFileDescriptor[T_file_co]

    @staticmethod
    async def make(epoller: Epoller, fd: FileDescriptor[T_file]) -> 'AsyncFileDescriptor[T_file]':
        await fd.set_nonblock()
        epolled = await epoller.register(fd, EpollEventMask.make(
            in_=True, out=True, rdhup=True, pri=True, err=True, hup=True, et=True))
        return AsyncFileDescriptor(epolled)

    def __init__(self, epolled: EpolledFileDescriptor[T_file_co]) -> None:
        self.epolled = epolled
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

            events = await self.epolled.wait()
            for event in events:
                if event.in_:   self.is_readable = True
                if event.out:   self.is_writable = True
                if event.rdhup: self.read_hangup = True
                if event.pri:   self.priority = True
                if event.err:   self.error = True
                if event.hup:   self.hangup = True
            self.running_wait = None
            running_wait.set()

    async def read(self: 'AsyncFileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        while True:
            try:
                return (await self.epolled.underlying.read(count))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                    while not (self.is_readable or self.read_hangup or self.hangup or self.error):
                        await self._wait_once()
                else:
                    raise

    async def write(self: 'AsyncFileDescriptor[WritableFile]', buf: bytes) -> None:
        while len(buf) > 0:
            try:
                written = await self.epolled.underlying.write(buf)
                buf = buf[written:]
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    # TODO this is not really quite right if it's possible to concurrently call methods on this object.
                    # we really need to lock while we're making the async call, right? maybe...
                    self.is_writable = False
                    while not (self.is_writable or self.error):
                        await self._wait_once()
                else:
                    raise

    async def accept(self: 'AsyncFileDescriptor[SocketFile[T_addr]]', flags: int=lib.SOCK_CLOEXEC
    ) -> t.Tuple[FileDescriptor[SocketFile[T_addr]], T_addr]:
        while True:
            try:
                return (await self.epolled.underlying.accept(flags))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                    while not (self.is_readable or self.hangup):
                        await self._wait_once()
                else:
                    raise

    async def connect(self: 'AsyncFileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        try:
            await self.epolled.underlying.connect(addr)
        except OSError as e:
            if e.errno == errno.EINPROGRESS:
                while not self.is_writable:
                    await self._wait_once()
                retbuf = await self.epolled.underlying.getsockopt(lib.SOL_SOCKET, lib.SO_ERROR, ffi.sizeof('int'))
                err = ffi.cast('int*', ffi.from_buffer(retbuf))[0]
                if err != 0:
                    raise OSError(err, os.strerror(err))
            else:
                raise

    async def aclose(self) -> None:
        await self.epolled.aclose()

    async def __aenter__(self) -> 'AsyncFileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

def _validate_path_and_task_match(task: Task, path: base.Path) -> None:
    if isinstance(path.base, base.DirfdPathBase):
        if path.base.dirfd.fd_namespace != task.fd_namespace:
            raise Exception("path", path, "based at a dirfd which isn't in the fd_namespace of task", task)
    elif isinstance(path.base, base.RootPathBase):
        if path.base.mount_namespace != task.mount:
            raise Exception("path", path, "based at root isn't in the mount namespace of task", task)
        if path.base.fs_information != task.fs:
            raise Exception("path", path, "based at root doesn't share fs information with task", task)
    elif isinstance(path.base, base.CWDPathBase):
        if path.base.mount_namespace != task.mount:
            raise Exception("path", path, "based at cwd isn't in the mount namespace of task", task)
        if path.base.fs_information != task.fs:
            raise Exception("path", path, "based at cwd doesn't share fs information with task", task)

class Directory:
    "This is a convenient combination of a pure path and a task to make syscalls in."
    def __init__(self, task: Task, pure: base.Path) -> None:
        self.task = task
        self.base = pure
        self.components = pure
        _validate_path_and_task_match(self.task, self.pure)
    pass

class Path:
    "This is a convenient combination of a pure path and a task to make syscalls in."
    def __init__(self, task: Task, pure: base.Path) -> None:
        self.task = task
        self.pure = pure
        _validate_path_and_task_match(self.task, self.pure)

    @staticmethod
    def from_bytes(task: Task, path: bytes) -> Path:
        if len(path) == 0:
            # readlink, and possibly other syscalls, behave differently when given an empty path and a dirfd
            # in general an empty path is probably not good
            # TODO okay actually maybe let's lift this restriction
            raise Exception("empty paths not allowed")
        if path.startswith(b"/"):
            return Path(task, base.Path(base.RootPathBase(task.mount, task.fs), path[1:]))
        else:
            return Path(task, base.Path(base.CWDPathBase(task.mount, task.fs), path))

    async def mkdir(self, mode=0o777) -> Path:
        await memsys.mkdirat(self.task.syscall, self.task.gateway, self.task.allocator,
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
        fd = await memsys.openat(self.task.syscall, self.task.gateway, self.task.allocator,
                                 self.pure, flags, mode)
        return self.task._make_fd(fd, file)

    async def open_directory(self) -> FileDescriptor[DirectoryFile]:
        return (await self.open(os.O_DIRECTORY))

    async def open_path(self) -> FileDescriptor[File]:
        return (await self.open(os.O_PATH))

    async def creat(self, mode=0o644) -> FileDescriptor[WritableFile]:
        fd = await memsys.openat(self.task.syscall, self.task.gateway, self.task.allocator,
                                 self.pure, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, mode)
        return self.task._make_fd(fd, WritableFile())

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
            await memsys.faccessat(self.task.syscall, self.task.gateway, self.task.allocator,
                                   self.pure, mode, 0)
            return True
        except OSError:
            return False

    async def unlink(self, flags: int=0) -> None:
        await memsys.unlinkat(self.task.syscall, self.task.gateway, self.task.allocator,
                              self.pure, flags)

    async def rmdir(self) -> None:
        await memsys.unlinkat(self.task.syscall, self.task.gateway, self.task.allocator,
                              self.pure, rsyscall.stat.AT_REMOVEDIR)

    async def link_to(self, oldpath: 'Path', flags: int=0) -> 'Path':
        "Create a hardlink at Path 'self' to the file at Path 'oldpath'"
        await memsys.linkat(self.task.syscall, self.task.gateway, self.task.allocator,
                            oldpath.pure, self.pure, flags)
        return self

    async def symlink_to(self, target: bytes) -> 'Path':
        "Create a symlink at Path 'self' pointing to the passed-in target"
        await memsys.symlinkat(self.task.syscall, self.task.gateway, self.task.allocator,
                               self.pure, target)
        return self

    async def readlink(self, bufsiz: int=4096) -> bytes:
        return (await memsys.readlinkat(self.task.syscall, self.task.gateway, self.task.allocator,
                                        self.pure, bufsiz))
    
    def _as_proc_path(self) -> bytes:
        """The path, using /proc to do dirfd-relative lookups

        This is not too portable - there are many situations where /proc might
        not be mounted. But if we have a dirfd-relative path, this is the only
        way to build an AF_UNIX sock address from the path or to pass the path
        to a subprocess.

        """
        purebase = self.pure.base
        if isinstance(purebase, base.DirfdPathBase):
            return b"/".join([b"/proc/self/fd", str(purebase.dirfd.number).encode(), self.pure.data])
        elif isinstance(purebase, base.RootPathBase):
            return b"/" + self.pure.data
        else:
            return self.pure.data

    async def as_argument(self) -> bytes:
        purebase = self.pure.base
        if isinstance(purebase, base.DirfdPathBase):
            # we disable cloexec to pass the dirfd as an argument.
            # this is somewhat weird to do without ownership, but whatever.
            await raw_syscall.fcntl(self.task.syscall, purebase.dirfd, fcntl.F_SETFD, 0)
        return self._as_proc_path()

    async def bind(self, fd: FileDescriptor[UnixSocketFile]) -> None:
        # TODO
        proc_path = self._as_proc_path()
        if len(proc_path) > 108:
            # if the filename is longer than 108,
            # then I need to do a temp name and rename
            # open the directory,
            # bind on temp 
            pass
        else:
            await fd.bind(UnixAddress(proc_path))

    async def connect(self, fd: FileDescriptor[UnixSocketFile]) -> None:
        proc_path = self._as_proc_path()
        # TODO don't hardcode 108
        if len(proc_path) > 108:
            # the path is too long to fit in a UnixAddress;
            # open the path as an O_PATH fd then use /proc/self/fd to do the connect
            # hmm I wonder if I should throw an exception and force the user to do this?
            # rather than automagically doing something slow?
            # I contend that Linux should really support this anyway,
            # so I think I'm fine with handling it automagically
            # hmm should it support doing this?
            async with (await self.open_path()) as pathfd:
                # hmm what if we just had some method directly on the fd to do the AT_EMPTY_PATH thing,
                # on a pathfd?
                # that seems wise, we would want to have that in any case
                # then what is the bind?
                # well, we operate on a directory, I guess, to create the socket...
                # should mkdirat and symlinkat and all those things have separated directory/name arguments?
                # dubious: openat means that's not needed.
                # on the other hand, we could currently pass a Path to a mkdirat/symlinkat,
                # and it might or might not be a directory entry.
                # so we could have things that we assert are directories,
                # and things which we assert are directory entries,
                # and sometimes a directory entry can also be a directory,
                # and so directory entry can also be a directory.
                # so do I have two separate classes?
                # or something?
                # I have Directory and DirectoryEntry?
                # and I can't determine what something is?
                # but doesn't that level of typing contradict the way paths usually work?
                # hmmmmmmmmmmmm
                # paths are really juts opaque pointers though...
                # hmmmmmmmmmmmmmmmmmmmmm
                # and we can use those pointers as either directories or directory entries
                # but some times we can ensure it's a directory by construction
                # and sometimes directory entries at runtime are directories
                # and only the ones
                # so, dirfds are always directories.
                # cwd and root are always directories.
                # other directories may be directory entries.
                await fd.connect(UnixAddress(
                    b"/".join([b"/proc/self/fd", str(pathfd.pure.number).encode()])))
        else:
            await fd.connect(UnixAddress(proc_path))

    def unix_address(self) -> UnixAddress:
        """Return an address that can be used with bind/connect for Unix sockets

        Linux doesn't support bindat/connectat or similar, so this is emulated with /proc.

        This will fail if the bytes component of the path is too long,
        because bind has a limit of 108 bytes for the pathname.

        """
        return UnixAddress(self._as_proc_path())

    def __truediv__(self, path_element: t.Union[str, bytes]) -> 'Path':
        element: bytes = os.fsencode(path_element)
        if b"/" in element:
            raise Exception("no / allowed in path elements, do it one by one")
        if self.pure.data == b'.':
            # if the path is empty, just be relative
            return Path(self.task, base.Path(self.pure.base, element))
        else:
            return Path(self.task, base.Path(self.pure.base, self.pure.data + b"/" + element))

    def __str__(self) -> str:
        return f"Path({self.pure})"

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

def gather_local_bootstrap() -> UnixBootstrap:
    syscall = LocalSyscall()
    pid = os.getpid()
    task = Task(syscall,
                LocalMemoryGateway(),
                base.FDNamespace(pid), base.local_address_space, base.MountNamespace(pid), base.FSInformation(pid),
                SignalMask(set()), base.ProcessNamespace(pid))
    argv = [arg.encode() for arg in sys.argv]
    environ = {key.encode(): value.encode() for key, value in os.environ.items()}
    stdstreams = wrap_stdin_out_err(task)
    return UnixBootstrap(task, argv, environ, stdstreams)


class ExecutableLookupCache:
    "Find executables by name, with a cache for the lookups"
    def __init__(self, paths: t.List[Path]) -> None:
        # we don't enforce that the paths are in the same mount
        # namespace or even the same host. that might lead to some
        # interesting/weird functionality.
        # execveat(fd) might be helpful here.
        self.paths = paths
        self.cache: t.Dict[bytes, Path] = {}

    async def uncached_lookup(self, name: bytes) -> t.Optional[Path]:
        if b"/" in name:
            raise Exception("name should be a single path element without any / present")
        for path in self.paths:
            filename = path/name
            if (await filename.access(read=True, execute=True)):
                return filename
        return None

    async def lookup(self, name: t.Union[str, bytes]) -> Path:
        basename: bytes = os.fsencode(name)
        if basename in self.cache:
            return self.cache[basename]
        else:
            result = await self.uncached_lookup(basename)
            if result is None:
                raise Exception(f"couldn't find {name}")
            # we don't cache negative lookups
            self.cache[basename] = result
            return result

@dataclass
class UnixUtilities:
    rm: Path
    sh: Path

async def build_unix_utilities(exec_cache: ExecutableLookupCache) -> UnixUtilities:
    rm = await exec_cache.lookup("rm")
    sh = await exec_cache.lookup("sh")
    return UnixUtilities(rm=rm, sh=sh)

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

class RemoteNew:
    def __init__(self, memory_allocator: memory.Allocator, memory_gateway: MemoryGateway) -> None:
        self.memory_allocator = memory_allocator
        self.memory_gateway = memory_gateway

    async def new(self, data: bytes) -> memory.Allocation:
        allocation = await self.memory_allocator.malloc(len(data))
        try:
            await self.memory_gateway.memcpy(allocation.pointer, to_local_pointer(data), len(data))
        except Exception:
            allocation.free()
        return allocation

@dataclass
class TaskResources:
    epoller: Epoller
    child_monitor: ChildTaskMonitor

    @staticmethod
    async def make(task: Task) -> TaskResources:
        epoller = await task.make_epoller()
        child_monitor = await ChildTaskMonitor.make(task, epoller)
        return TaskResources(epoller, child_monitor)

    async def close(self) -> None:
        # have to destruct in opposite order of construction, gee that sounds like C++
        # ¯\_(ツ)_/¯
        await self.child_monitor.close()
        await self.epoller.close()

    async def __aenter__(self) -> TaskResources:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()


@dataclass
class ProcessResources:
    server_func: FunctionPointer
    do_cloexec_func: FunctionPointer
    futex_helper_func: FunctionPointer
    memory_allocator: memory.Allocator

    @staticmethod
    def make_from_local(task: Task) -> 'ProcessResources':
        # TODO let's make a memory allocator!
        # right? yes!
        return ProcessResources(
            server_func=FunctionPointer(task.address_space, ffi.cast('long', lib.rsyscall_server)),
            do_cloexec_func=FunctionPointer(task.address_space, ffi.cast('long', lib.rsyscall_do_cloexec)),
            futex_helper_func=FunctionPointer(task.address_space, ffi.cast('long', lib.rsyscall_futex_helper)),
            memory_allocator=memory.Allocator(task.syscall, task.address_space),
        )

    async def decref(self) -> None:
        # TODO oops this won't work probably humm
        # we need some kind of reference counting
        await self.memory_allocator.close()

@dataclass
class FilesystemResources:
    # various things picked up by environment variables
    executable_lookup_cache: ExecutableLookupCache
    tmpdir: Path
    # utilities are eagerly looked up in PATH
    utilities: UnixUtilities
    # locale?
    # home directory?

    @staticmethod
    async def make_from_bootstrap(task: Task, bootstrap: UnixBootstrap) -> 'FilesystemResources':
        executable_dirs: t.List[Path] = []
        for prefix in bootstrap.environ[b"PATH"].split(b":"):
            executable_dirs.append(Path.from_bytes(task, prefix))
        executable_lookup_cache = ExecutableLookupCache(executable_dirs)
        tmpdir = Path.from_bytes(task, bootstrap.environ[b"TMPDIR"])
        utilities = await build_unix_utilities(executable_lookup_cache)
        return FilesystemResources(
            executable_lookup_cache=executable_lookup_cache,
            tmpdir=tmpdir,
            utilities=utilities,
        )

class BatchGatewayOperation:
    def __init__(self, gateway: MemoryGateway) -> None:
        self.gateway = gateway
        self.operations: t.List[t.Tuple[Pointer, Pointer, int]] = []

    def memcpy(self, dest: Pointer, src: Pointer, n: int) -> None:
        self.operations.append((dest, src, n))

    async def flush(self) -> None:
        raise Exception("use iovec magic to do the copy, woo")

class Serializer:
    def __init__(self, memory_allocator: memory.Allocator, async_exit_stack: contextlib.AsyncExitStack) -> None:
        self.memory_allocator = memory_allocator
        self.async_exit_stack = async_exit_stack
        self.operations: t.List[t.Tuple[Pointer, bytes]] = []

    async def serialize(self, data: bytes) -> Pointer:
        # we could defer allocation to the end and do it in bulk, but I can't figure out how to
        # model that, since we need to have the pointers to the allocated memory to serialize argv.
        allocation = await self.memory_allocator.malloc(len(data))
        ptr: Pointer = self.async_exit_stack.enter_context(allocation)
        self.operations.append((ptr, data))
        return ptr

    async def flush(self, gateway: MemoryGateway) -> None:
        batch = BatchGatewayOperation(gateway)
        for ptr, data in self.operations:
            batch.memcpy(ptr, to_local_pointer(data), len(data))
        await batch.flush()

class StandardTask:
    def __init__(self,
                 task: Task,
                 task_resources: TaskResources,
                 process_resources: ProcessResources,
                 filesystem_resources: FilesystemResources,
                 environment: t.Dict[bytes, bytes],
    ) -> None:
        self.task = task
        self.resources = task_resources
        self.process = process_resources
        self.filesystem = filesystem_resources
        self.environment = environment

    @staticmethod
    async def make_from_bootstrap(bootstrap: UnixBootstrap) -> 'StandardTask':
        task = bootstrap.task
        # TODO fix this to... pull it from the bootstrap or something...
        process_resources = ProcessResources.make_from_local(task)
        task_resources = await TaskResources.make(task)
        filesystem_resources = await FilesystemResources.make_from_bootstrap(task, bootstrap)
        return StandardTask(task, task_resources, process_resources, filesystem_resources,
                            {**bootstrap.environ})

    async def mkdtemp(self, prefix: str="mkdtemp") -> 'TemporaryDirectory':
        parent = self.filesystem.tmpdir
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = (prefix+"."+random_suffix).encode()
        await (parent/name).mkdir(mode=0o700)
        return TemporaryDirectory(self, parent, name)

    async def spawn(self,
                    user_fds: t.List[FileDescriptor],
                    shared: UnshareFlag=UnshareFlag.FS,
    ) -> t.Tuple['RsyscallTask', t.List[FileDescriptor]]:
        thread_maker = ThreadMaker(self.task.gateway, self.resources.child_monitor)
        task, cthread, fds = await rsyscall_spawn(
            self.task, thread_maker, self.resources.epoller, self.process.server_func,
            user_fds, shared)
        # TODO maybe need to think some more about how this resource inheriting works
        # for that matter, could I inherit the epollfd and signalfd across tasks?
        stdtask = StandardTask(task, await TaskResources.make(task),
                               self.process, self.filesystem, {**self.environment})
        return RsyscallTask(stdtask, cthread), fds

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
        await self.resources.close()
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
        new_task, _ = await self.stdtask.spawn([], shared=UnshareFlag.NONE)
        async with new_task:
            # TODO would be nice if unsharing the fs information gave us a cap to chdir
            await new_task.stdtask.task.chdir(self.parent)
            child = await new_task.execve(self.stdtask.filesystem.utilities.rm, ["rm", "-r", self.name])
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
            raise Exception("can't allocate a SignalBlock for a signal that was already blocked")
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
    async def make(cls, task: Task, epoller: Epoller, mask: t.Set[signal.Signals]) -> 'SignalQueue':
        signal_block = await SignalBlock.make(task, mask)
        sigfd = await task.signalfd_create(mask)
        async_sigfd = await AsyncFileDescriptor.make(epoller, sigfd)
        return cls(signal_block, async_sigfd)

    async def read(self) -> None:
        data = await self.sigfd.read()
        # TODO need to return this data in some parsed form
        data = ffi.cast('struct signalfd_siginfo*', ffi.from_buffer(data))

    async def close(self) -> None:
        await self.signal_block.close()
        await self.sigfd.aclose()

    async def __aenter__(self) -> 'SignalQueue':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class MultiplexerQueue:
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
        return self.monitor.signal_queue.sigfd.epolled.underlying.task.syscall

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
    async def make(task: Task, epoller: Epoller) -> 'ChildTaskMonitor':
        signal_queue = await SignalQueue.make(task, epoller, {signal.SIGCHLD})
        return ChildTaskMonitor(signal_queue)

    def __init__(self, signal_queue: SignalQueue) -> None:
        self.signal_queue = signal_queue
        self.task_map: t.Dict[int, ChildTask] = {}
        self.unknown_queue = trio.hazmat.UnboundedQueue()
        self.wait_lock = trio.Lock()
        if self.signal_queue.sigfd.epolled.underlying.file.mask != set([signal.SIGCHLD]):
            raise Exception("ChildTaskMonitor should get a SignalQueue only for SIGCHLD")
        self.running_wait: t.Optional[trio.Event] = None

    async def clone(self, flags: int,
                    child_stack: Pointer, ctid: Pointer, newtls: Pointer) -> ChildTask:
        task = self.signal_queue.sigfd.epolled.underlying.task
        tid = await raw_syscall.clone(task.syscall, flags, child_stack,
                                      ptid=None, ctid=ctid, newtls=newtls)
        child_task = ChildTask(base.Process(task.process_namespace, tid), trio.hazmat.UnboundedQueue(), self)
        self.task_map[tid] = child_task
        return child_task

    async def do_wait(self) -> None:
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait

            # we don't care what information we get from the signal, we just want to
            # sleep until a SIGCHLD happens
            await self.signal_queue.read()
            # loop on waitid to flush all child events
            task = self.signal_queue.sigfd.epolled.underlying.task
            # only handle a maximum of 32 child events before returning, to prevent a DOS-through-forkbomb
            # TODO if we could just detect when the ChildTask that we are wait()ing for
            # has gotten an event, we could handle events in this function indefinitely,
            # and only return once we've sent an event to that ChildTask.
            # maybe by passing in the waiting queue?
            # could do the same for epoll too.
            # though we have to wake other people up too...
            for _ in range(32):
                try:
                    # have to serialize against things which use pids; we can't do a wait
                    # while something else is making a syscall with a pid, because we
                    # might collect the zombie for that pid and cause pid reuse
                    async with self.wait_lock:
                        siginfo = await memsys.waitid(task.syscall, task.gateway, task.allocator,
                                                      None, lib._WALL|lib.WEXITED|lib.WSTOPPED|lib.WCONTINUED|lib.WNOHANG)
                except ChildProcessError:
                    # no more children
                    break
                struct = ffi.cast('siginfo_t*', ffi.from_buffer(siginfo))
                if struct.si_pid == 0:
                    # no more waitable events, but we still have children
                    break
                child_event = ChildEvent.make(ChildCode(struct.si_code),
                                              pid=int(struct.si_pid), uid=int(struct.si_uid),
                                              status=int(struct.si_status))
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

            self.running_wait = None
            running_wait.set()

    async def close(self) -> None:
        await self.signal_queue.close()

    async def __aenter__(self) -> 'ChildTaskMonitor':
        return self

    async def __aexit__(self, *args, **kwargs):
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

    It would better if we could just get notified of mm_release through SIGCHLD/waitid.

    """
    child_task: ChildTask
    futex_task: ChildTask
    futex_mapping: memory.AnonymousMapping
    def __init__(self, child_task: ChildTask, futex_task: ChildTask, futex_mapping: memory.AnonymousMapping) -> None:
        self.child_task = child_task
        self.futex_task = futex_task
        self.futex_mapping = futex_mapping
        self.released = False

    async def wait_for_mm_release(self) -> ChildTask:
        """Wait for the task to leave the parent's address space, and return the ChildTask.

        The task can leave the parent's address space either by exiting or execing.

        """
        # once the futex task has exited, the child task has left the parent's address space.
        result = await self.futex_task.wait_for_exit()
        if not result.clean():
            raise Exception("the futex task", self.futex_task, "for child task", self.child_task,
                            "unexpectedly exited non-zero", result, "maybe it was SIGKILL'd?")
        await self.futex_mapping.unmap()
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

class CThread:
    """A thread running the C runtime and some C function.

    At the moment, that means it has a stack. 
    The considerations for the Thread class all therefore apply.

    TODO thread-local-storage.

    """
    thread: Thread
    stack_mapping: memory.AnonymousMapping
    def __init__(self, thread: Thread, stack_mapping: memory.AnonymousMapping) -> None:
        self.thread = thread
        self.stack_mapping = stack_mapping

    async def wait_for_mm_release(self) -> ChildTask:
        result = await self.thread.wait_for_mm_release()
        # we can free the stack mapping now that the thread has left our address space
        await self.stack_mapping.unmap()
        return result

    async def close(self) -> None:
        await self.thread.close()
        await self.wait_for_mm_release()

    async def __aenter__(self) -> 'CThread':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

def build_trampoline_stack(function: FunctionPointer, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> bytes:
    # TODO clean this up with dicts or tuples or something
    stack_struct = ffi.new('struct rsyscall_trampoline_stack*')
    stack_struct.rdi = int(arg1)
    stack_struct.rsi = int(arg2)
    stack_struct.rdx = int(arg3)
    stack_struct.rcx = int(arg4)
    stack_struct.r8  = int(arg5)
    stack_struct.r9  = int(arg6)
    stack_struct.function = ffi.cast('void*', function.address)
    trampoline_addr = int(ffi.cast('long', lib.rsyscall_trampoline))
    packed_trampoline_addr = struct.pack('Q', trampoline_addr)
    stack = packed_trampoline_addr + bytes(ffi.buffer(stack_struct))
    return stack

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
        offset = self.allocation_pointer.address % alignment
        self.push(bytes(offset))

    async def flush(self, gateway) -> Pointer:
        await gateway.memcpy(self.allocation_pointer, to_local_pointer(self.buffer), len(self.buffer))
        self.buffer = b""
        return self.allocation_pointer

class ThreadMaker:
    def __init__(self, gateway: MemoryGateway, monitor: ChildTaskMonitor) -> None:
        self.gateway = gateway
        self.monitor = monitor
        task = monitor.signal_queue.sigfd.epolled.underlying.task
        # TODO pull this function out of somewhere sensible
        self.futex_func = FunctionPointer(task.address_space, ffi.cast('long', lib.rsyscall_futex_helper))

    async def clone(self, flags: int, child_stack: Pointer, newtls: Pointer) -> Thread:
        """Provides an asynchronous interface to the CLONE_CHILD_CLEARTID functionality

        Executes the instruction "ret" immediately after cloning.

        """
        if not (flags & lib.CLONE_VM):
            # TODO let's figure out how to force the futex address to be shared memory with the
            # child, by mapping a memfd instead of using CLONE_PRIVATE 
            raise Exception("CLONE_VM is mandatory right now because I'm lazy")
        task = self.monitor.signal_queue.sigfd.epolled.underlying.task
        # allocate memory for the stack
        stack_size = 4096
        mapping = await task.mmap(stack_size, memory.ProtFlag.READ|memory.ProtFlag.WRITE, memory.MapFlag.PRIVATE)
        stack = BufferedStack(mapping.pointer + stack_size)
        # allocate the futex at the base of the stack, with "1" written to it to match
        # what futex_helper expects
        futex_pointer = stack.push(struct.pack('i', 1))
        # align the stack to a 16-bit boundary now, so after pushing the trampoline data,
        # which the trampoline will all pop off, the stack will be aligned.
        stack.align()
        # build the trampoline and push it on the stack
        stack.push(build_trampoline_stack(self.futex_func, futex_pointer))
        # copy the stack over
        stack_pointer = await stack.flush(self.gateway)
        # start the task
        futex_task = await self.monitor.clone(
            lib.CLONE_VM|lib.CLONE_FILES|signal.SIGCHLD, stack_pointer,
            ctid=task.address_space.null(), newtls=task.address_space.null())
        # wait for futex helper to SIGSTOP itself,
        # which indicates the trampoline is done and we can deallocate the stack.
        event = await futex_task.wait_for_stop_or_exit()
        if event.died():
            raise Exception("thread internal futex-waiting task died unexpectedly", event)
        # resume the futex_task so it can start waiting on the futex
        await futex_task.send_signal(signal.SIGCONT)
        # the only part of the memory mapping that's being used now is the futex address, which is a
        # huge waste. oh well, later on we can allocate futex addresses out of a shared mapping.
        child_task = await self.monitor.clone(
            flags | lib.CLONE_CHILD_CLEARTID, child_stack,
            ctid=futex_pointer, newtls=newtls)
        return Thread(child_task, futex_task, mapping)

    async def make_cthread(self, flags: int,
                          function: FunctionPointer, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0,
    ) -> CThread:
        task = self.monitor.signal_queue.sigfd.epolled.underlying.task
        # allocate memory for the stack
        stack_size = 4096
        mapping = await task.mmap(stack_size, memory.ProtFlag.READ|memory.ProtFlag.WRITE, memory.MapFlag.PRIVATE)
        stack = BufferedStack(mapping.pointer + stack_size)
        # build stack
        stack.push(build_trampoline_stack(function, arg1, arg2, arg3, arg4, arg5, arg6))
        # copy the stack over
        stack_pointer = await stack.flush(self.gateway)
        # TODO actually allocate TLS
        tls = task.address_space.null()
        thread = await self.clone(flags|signal.SIGCHLD, stack_pointer, tls)
        return CThread(thread, mapping)

class RsyscallConnection:
    """A connection to some rsyscall server where we can make syscalls
    """
    def __init__(self,
                 tofd: AsyncFileDescriptor[WritableFile],
                 fromfd: AsyncFileDescriptor[ReadableFile],
    ) -> None:
        self.tofd = tofd
        self.fromfd = fromfd
        self.request_lock = trio.Lock()
        self.response_fifo_lock = trio.StrictFIFOLock()

    async def close(self) -> None:
        await self.tofd.aclose()
        await self.fromfd.aclose()

    async def syscall(self, number: int, arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> int:
        request = ffi.new('struct rsyscall_syscall*',
                          (number, (arg1, arg2, arg3, arg4, arg5, arg6)))
        async with self.request_lock:
            try:
                await self.tofd.write(bytes(ffi.buffer(request)))
            except OSError as e:
                # we raise a different exception so that users can distinguish syscall errors from
                # transport errors
                raise RsyscallException() from e
        async with self.response_fifo_lock:
            try:
                response_bytes = await self.fromfd.read(ffi.sizeof('unsigned long'))
            except OSError as e:
                raise RsyscallException() from e
        if len(response_bytes) == 0:
            # we catch this in the implementations of exec and exit
            raise RsyscallHangup()
        response, = struct.unpack('q', response_bytes)
        return response

class RsyscallLocalSyscall(base.SyscallInterface):
    def __init__(self, rsyscall_connection: RsyscallConnection, process: base.Process, infd: base.FileDescriptor, outfd: base.FileDescriptor) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.other_activity_fd = infd.number
        self.infd = infd
        self.outfd = outfd
        self.process = process
        self.logger = logging.getLogger(f"rsyscall.RsyscallConnection.{self.process.id}")

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        ret = await self.rsyscall_connection.syscall(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        if ret < 0:
            err = -ret
            raise OSError(err, os.strerror(err))
        return ret

async def call_function(task: Task, stack: BufferedStack, function: FunctionPointer, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> ChildEvent:
    "Calls a C function and waits for it to complete. Returns the ChildEvent that the child thread terminated with."
    stack.align()
    stack.push(build_trampoline_stack(function, arg1, arg2, arg3, arg4, arg5, arg6))
    stack_pointer = await stack.flush(task.gateway)
    # we directly spawn a thread for the function and wait on it
    pid = await raw_syscall.clone(task.syscall, lib.CLONE_VM|lib.CLONE_FILES, stack_pointer, ptid=None, ctid=None, newtls=None)
    process = base.Process(task.process_namespace, pid)
    siginfo = await memsys.waitid(task.syscall, task.gateway, task.allocator,
                                  process, lib._WALL|lib.WEXITED)
    struct = ffi.cast('siginfo_t*', ffi.from_buffer(siginfo))
    child_event = ChildEvent.make(ChildCode(struct.si_code),
                                  pid=int(struct.si_pid), uid=int(struct.si_uid),
                                  status=int(struct.si_status))
    return child_event

async def do_cloexec_except(task: Task, excluded_fd_numbers: t.Iterable[int]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    function = FunctionPointer(task.address_space, ffi.cast('long', lib.rsyscall_do_cloexec))
    stack_size = 4096
    async with (await task.mmap(stack_size, memory.ProtFlag.READ|memory.ProtFlag.WRITE, memory.MapFlag.PRIVATE)) as mapping:
        stack = BufferedStack(mapping.pointer + stack_size)
        fd_array = array.array('i', excluded_fd_numbers)
        fd_array_ptr = stack.push(fd_array.tobytes())
        child_event = await call_function(task, stack, function, fd_array_ptr, len(fd_array))
        if not child_event.clean():
            raise Exception("cloexec function child died!", child_event)

async def rsyscall_spawn(task: Task, thread_maker: ThreadMaker, epoller: Epoller, function: FunctionPointer,
                         user_fds: t.List[FileDescriptor],
                         shared: UnshareFlag=UnshareFlag.FS,
    ) -> t.Tuple[Task, CThread, t.List[FileDescriptor]]:
    "Spawn an rsyscall server running in a child task"
    for fd in user_fds:
        if fd.pure.fd_namespace is not task.fd_namespace:
            raise Exception("can only translate file descriptors from my fd namespace")
    pipe_in = await task.pipe()
    pipe_out = await task.pipe()
    # new fd namespace is created here
    cthread = await thread_maker.make_cthread(
        lib.CLONE_VM|shared, function, pipe_in.rfd.pure.number, pipe_out.wfd.pure.number)
    process = cthread.thread.child_task.process

    async_tofd = await AsyncFileDescriptor.make(epoller, pipe_in.wfd)
    async_fromfd = await AsyncFileDescriptor.make(epoller, pipe_out.rfd)
    syscall = RsyscallLocalSyscall(RsyscallConnection(async_tofd, async_fromfd),
                                   cthread.thread.child_task.process,
                                   pipe_in.rfd.pure, pipe_out.wfd.pure)
    # TODO remove assumption that we are local
    gateway = LocalMemoryGateway()

    new_task = Task(syscall, gateway,
                    base.FDNamespace(process.id), task.address_space, task.mount, task.fs,
                    task.sigmask.inherit(), task.process_namespace)
    if len(new_task.sigmask.mask) != 0:
        # clear this non-empty signal mask because it's pointlessly inherited across fork
        await new_task.sigmask.setmask(new_task, set())

    inherited_fd_numbers: t.Set[int] = {pipe_in.rfd.pure.number, pipe_out.wfd.pure.number}
    await pipe_in.rfd.aclose()
    await pipe_out.wfd.aclose()

    def translate(fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
        inherited_fd_numbers.add(fd.pure.number)
        return new_task._make_fd(fd.pure.number, fd.file)
    inherited_user_fds = [translate(fd) for fd in user_fds]

    # close everything that's cloexec and not explicitly passed down
    await do_cloexec_except(new_task, inherited_fd_numbers)
    return new_task, cthread, inherited_user_fds

class RsyscallTask:
    def __init__(self,
                 stdtask: StandardTask,
                 thread: CThread,
    ) -> None:
        self.stdtask = stdtask
        self.thread = thread

    async def execve(self, path: Path, argv: t.Sequence[t.Union[str, bytes, Path]],
                     envp: t.Mapping[t.Union[str, bytes], t.Union[str, bytes, Path]]={},
    ) -> ChildTask:
        await self.stdtask.execve(path, argv, envp)
        # we return the still-running ChildTask that was inside this RsyscallTask
        return (await self.thread.wait_for_mm_release())

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

def extract_task(arg):
    if isinstance(arg, Task):
        return arg
    elif isinstance(arg, FileDescriptor):
        return arg.task
    elif isinstance(arg, Path):
        return arg.task

def assert_same_task(task: Task, *args) -> None:
    for arg in args:
        if isinstance(arg, Path):
            _validate_path_and_task_match(task, arg.pure)
        elif isinstance(arg, FileDescriptor):
            if arg.task != task:
                raise Exception("desired task", task, "doesn't match task", arg.task, "in arg", arg)
        else:
            raise Exception("can't validate argument", arg)
                
# compare this, with task_status arguments:
async def run_foo(arg1, arg2, *, task_status=trio.TASK_STATUS_IGNORED):
    internal_data = await frobnicate(arg1, arg2)
    async with trio.open_nursery() as nursery:
        internal_object = await nursery.start(run_foo_internal, internal_data)
        task_status.started(internal_object.userobject())

async def run_foo_internal(internal_data, *, task_status=trio.TASK_STATUS_IGNORED):
    for thing in internal_data.things:
        await prepare(thing)
    async with trio.open_nursery() as nursery:
        await nursery.start(low_level_other_thing, internal_data.geta(), internal_data.getb())
        task_status.started()
    
# to this, with nursery arguments:
async def run_foo(nursery, arg1, arg2):
    internal_data = await frobnicate(arg1, arg2)
    internal_object = await run_foo_internal(nursery, internal_data)
    return internal_object.userobject()

async def run_foo_internal(nursery, internal_data):
    for thing in internal_data.things:
        await prepare(thing)
    await nursery.start(low_level_other_thing, internal_data.geta(), internal_data.getb())

# run_foo can even be simplified to:
async def run_foo(nursery, arg1, arg2):
    return (await run_foo_internal(nursery, await frobnicate(arg1, arg2))).userobject()

async def run_foo_internal(internal_data, *, task_status=trio.TASK_STATUS_IGNORED):
    for thing in internal_data.things:
        await prepare(thing)
    async with trio.open_nursery() as nursery:
        await nursery.start(low_level_other_thing, internal_data.geta(), internal_data.getb())
        task_status.started()
