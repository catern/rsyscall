from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.epoll import EpollEvent, EpollEventMask, EPOLL_CLOEXEC
import rsyscall.epoll
from rsyscall.stat import StatxResult
from rsyscall.stat import Dirent, DType
import rsyscall.stat
import supervise_api as supervise
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
import sfork
from async_generator import asynccontextmanager
from dataclasses import dataclass
import logging
import fcntl
import errno
import enum
logger = logging.getLogger(__name__)

class Rusage:
    pass

def rusage_parse(data: bytes) -> Rusage:
    return Rusage()

class IdType(enum.IntEnum):
    PID = lib.P_PID # Wait for the child whose process ID matches id.
    PGID = lib.P_PGID # Wait for any child whose process group ID matches id.
    ALL = lib.P_ALL # Wait for any child; id is ignored.

class SigprocmaskHow(enum.IntEnum):
    BLOCK = lib.SIG_BLOCK
    UNBLOCK = lib.SIG_UNBLOCK
    SETMASK = lib.SIG_SETMASK

def bits(n):
    "Yields the bit indices that are set"
    while n:
        b = n & (~n+1)
        yield b.bit_length()
        n ^= b

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
            return ChildEvent(code, pid, uid, status, None) # type: ignore
        else:
            return ChildEvent(code, pid, uid, None, signal.Signals(status)) # type: ignore

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

class SyscallInterface:
    async def pipe(self, flags=os.O_NONBLOCK) -> t.Tuple[int, int]: ...
    async def close(self, fd: int) -> None: ...
    # TODO add optional offset argument?
    # TODO figure out how to allow preadv2 flags?
    async def read(self, fd: int, count: int) -> bytes: ...
    async def write(self, fd: int, buf: bytes) -> int: ...
    async def dup2(self, oldfd: int, newfd: int) -> int: ...
    async def wait_readable(self, fd: int) -> None: ...

    # task manipulation
    async def clone(self, flags: int, child_stack: int, ptid: int, ctid: int, newtls: int) -> int: ...
    async def exit(self, status: int) -> None: ...
    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> None: ...

    async def getpid(self) -> int: ...

    async def kill(self, pid: int, sig: signal.Signals) -> None: ...

    async def mmap(self, addr: int, length: int, prot: int, flags: int, fd: int, offset: int) -> int: ...
    async def munmap(self, addr: int, length: int) -> int: ...

    # epoll operations
    async def epoll_create(self, flags: int) -> int: ...
    async def epoll_ctl_add(self, epfd: int, fd: int, event: EpollEvent) -> None: ...
    async def epoll_ctl_mod(self, epfd: int, fd: int, event: EpollEvent) -> None: ...
    async def epoll_ctl_del(self, epfd: int, fd: int) -> None: ...
    async def epoll_wait(self, epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]: ...

    # we can do the same with ioctl
    # but not with prctl. what a mistake prctl is!

    @t.overload
    async def fcntl(self, fd: int, cmd: int, arg: int=0) -> int: ...
    @t.overload
    async def fcntl(self, fd: int, cmd: int, arg: bytes) -> bytes: ...
    async def fcntl(self, fd, cmd, arg=0):
        "This follows the same protocol as fcntl.fcntl."
        ...

    # for prctl we will have a separate method for each usage mode;
    # its interface is too diverse to do anything else and still abstract over the details of memory
    async def prctl_set_child_subreaper(self, flag: bool) -> None: ...

    # statx returns a fixed-sized buffer which we parse outside the SyscallInterface
    async def statx(self, dirfd: int, pathname: bytes, flags: int, mask: int) -> bytes: ...

    async def faccessat(self, dirfd: int, pathname: bytes, mode: int, flags: int) -> None: ...

    async def chdir(self, path: bytes) -> None: ...
    async def fchdir(self, fd: int) -> None: ...

    async def openat(self, dirfd: int, pathname: bytes, flags: int, mode: int) -> int: ...
    async def mkdirat(self, dirfd: int, pathname: bytes, mode: int) -> None: ...
    async def getdents(self, fd: int, count: int) -> t.List[Dirent]: ...
    async def lseek(self, fd: int, offset: int, whence: int) -> int: ...
    async def unlinkat(self, dirfd: int, pathname: bytes, flags: int) -> None: ...
    async def linkat(self, olddirfd: int, oldpath: bytes, newdirfd: int, newpath: bytes, flags: int) -> None: ...
    async def symlinkat(self, target: bytes, newdirfd: int, newpath: bytes) -> None: ...
    async def readlinkat(self, dirfd: int, pathname: bytes, bufsiz: int) -> bytes: ...
    async def waitid(self, idtype: IdType, id: int, options: int, *, want_child_event: bool, want_rusage: bool
    ) -> t.Tuple[int, t.Optional[bytes], t.Optional[bytes]]: ...
    async def signalfd(self, fd: int, signals: t.Set[signal.Signals], flags: int) -> int: ...
    async def rt_sigprocmask(self, how: SigprocmaskHow, set: t.Optional[t.Set[signal.Signals]]) -> t.Set[signal.Signals]: ...

    # socket stuff
    async def socket(self, domain: int, type: int, protocol: int) -> int: ...
    async def socketpair(self, domain: int, type: int, protocol: int) -> t.Tuple[int, int]: ...

    async def bind(self, sockfd: int, addr: bytes) -> None: ...
    async def listen(self, sockfd: int, backlog: int) -> None: ...
    async def connect(self, sockfd: int, addr: bytes) -> None: ...
    async def accept(self, sockfd: int, addrlen: int, flags: int) -> t.Tuple[int, bytes]: ...
    async def getsockname(self, sockfd: int, addrlen: int) -> bytes: ...
    async def getpeername(self, sockfd: int, addrlen: int) -> bytes: ...

    async def getsockopt(self, sockfd: int, level: int, optname: int, optlen: int) -> bytes: ...
    async def setsockopt(self, sockfd: int, level: int, optname: int, optval: t.Optional[bytes], *, optlen: t.Optional[int]=None) -> None: ...

async def direct_syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
    "Make a syscall directly in the current thread."
    args = (ffi.cast('long', arg1), ffi.cast('long', arg2), ffi.cast('long', arg3),
            ffi.cast('long', arg4), ffi.cast('long', arg5), ffi.cast('long', arg6),
            number)
    ret = lib.rsyscall_raw_syscall(*args)
    return ret

def null_terminated(data: bytes):
    return ffi.new('char[]', data)

class LocalSyscall(SyscallInterface):
    def __init__(self, wait_readable, do_syscall) -> None:
        self._wait_readable = wait_readable
        self._do_syscall = do_syscall

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        ret = await self._do_syscall(number, arg1=arg1, arg2=arg2, arg3=arg3, arg4=arg4, arg5=arg5, arg6=arg6)
        if ret < 0:
            err = -ret
            raise OSError(err, os.strerror(err))
        return ret

    async def wait_readable(self, fd: int) -> None:
        logger.debug("wait_readable(%s)", fd)
        await self._wait_readable(fd)

    async def pipe(self, flags=os.O_CLOEXEC) -> t.Tuple[int, int]:
        logger.debug("pipe(%s)", flags)
        buf = ffi.new('int[2]')
        await self.syscall(lib.SYS_pipe2, buf, flags)
        return (buf[0], buf[1])

    async def close(self, fd: int) -> None:
        logger.debug("close(%d)", fd)
        await self.syscall(lib.SYS_close, fd)

    # I could switch to preadv2 as my primitive; I can avoid overhead
    # by storing the iovec and data as a single big buffer.
    async def read(self, fd: int, count: int) -> bytes:
        logger.debug("read(%d, %d)", fd, count)
        buf = ffi.new('char[]', count)
        ret = await self.syscall(lib.SYS_read, fd, buf, count)
        return bytes(ffi.buffer(buf, ret))

    async def write(self, fd: int, buf: bytes) -> int:
        logger.debug("write(%d, %s)", fd, buf)
        ret = await self.syscall(lib.SYS_write, fd, ffi.from_buffer(buf), len(buf))
        return ret

    async def dup2(self, oldfd: int, newfd: int) -> int:
        logger.debug("dup2(%d, %d)", oldfd, newfd)
        return (await self.syscall(lib.SYS_dup2, oldfd, newfd))

    async def clone(self, flags: int, child_stack: int, ptid: int, ctid: int, newtls: int) -> int:
        logger.debug("clone(%s, %s, %s, %s, %s)", flags, child_stack, ptid, ctid, newtls)
        return (await self.syscall(lib.SYS_clone, flags, child_stack, ptid, ctid, newtls))

    async def exit(self, status: int) -> None:
        logger.debug("exit(%d)", status)
        try:
            await self.syscall(lib.SYS_exit, status)
        except RsyscallHangup:
            # a hangup means the exit was successful
            pass

    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> None:
        logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
        # this null-terminated-array logic is tricky to extract out into a separate function due to lifetime issues
        null_terminated_args = [ffi.new('char[]', arg) for arg in argv]
        argv_bytes = ffi.new('char *const[]', null_terminated_args + [ffi.NULL])
        null_terminated_env_vars = [ffi.new('char[]', arg) for arg in envp]
        envp_bytes = ffi.new('char *const[]', null_terminated_env_vars + [ffi.NULL])
        path_bytes = ffi.new('char[]', path)
        try:
            await self.syscall(lib.SYS_execveat, dirfd, path_bytes, argv_bytes, envp_bytes, flags)
        except RsyscallHangup:
            # a hangup means the exec was successful. other exceptions will propagate through
            pass

    async def mmap(self, addr: int, length: int, prot: int, flags: int, fd: int, offset: int) -> int:
        logger.debug("mmap(%s, %s, %s, %s, %s, %s)", addr, length, prot, flags, fd, offset)
        return (await self.syscall(lib.SYS_mmap, addr, length, prot, flags, fd, offset))

    async def munmap(self, addr: int, length: int) -> int:
        logger.debug("munmap(%s, %s)", addr, length)
        return (await self.syscall(lib.SYS_munmap, addr, length))

    async def exit_group(self, status: int) -> None:
        logger.debug("exit_group(%d)", status)
        await self.syscall(lib.SYS_exit_group, status)

    async def getpid(self) -> int:
        logger.debug("getpid()")
        return (await self.syscall(lib.SYS_getpid))

    async def epoll_create(self, flags: int) -> int:
        logger.debug("epoll_create(%s)", flags)
        return (await self.syscall(lib.SYS_epoll_create1, flags))

    async def epoll_ctl_add(self, epfd: int, fd: int, event: EpollEvent) -> None:
        logger.debug("epoll_ctl_add(%d, %d, %s)", epfd, fd, event)
        await self.syscall(lib.SYS_epoll_ctl, epfd, lib.EPOLL_CTL_ADD, fd, event.to_bytes())

    async def epoll_ctl_mod(self, epfd: int, fd: int, event: EpollEvent) -> None:
        logger.debug("epoll_ctl_mod(%d, %d, %s)", epfd, fd, event)
        await self.syscall(lib.SYS_epoll_ctl, epfd, lib.EPOLL_CTL_MOD, fd, event.to_bytes())

    async def epoll_ctl_del(self, epfd: int, fd: int) -> None:
        logger.debug("epoll_ctl_del(%d, %d)", epfd, fd)
        await self.syscall(lib.SYS_epoll_ctl, epfd, lib.EPOLL_CTL_DEL, fd)

    async def epoll_wait(self, epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]:
        logger.debug("epoll_wait(%d, maxevents=%d, timeout=%d)", epfd, maxevents, timeout)
        c_events = ffi.new('struct epoll_event[]', maxevents)
        count = await self.syscall(lib.SYS_epoll_wait, epfd, c_events, maxevents, timeout)
        ret = []
        for ev in c_events[0:count]:
            ret.append(EpollEvent(ev.data.u64, EpollEventMask(ev.events)))
        return ret

    @t.overload
    async def fcntl(self, fd: int, cmd: int, arg: int=0) -> int: ...
    @t.overload
    async def fcntl(self, fd: int, cmd: int, arg: bytes) -> bytes:
        "This follows the same protocol as fcntl.fcntl."
        ...
    async def fcntl(self, fd: int, cmd: int, arg=0) -> t.Union[bytes, int]:
        "This follows the same protocol as fcntl.fcntl."
        logger.debug("fcntl(%d, %d, %s)", fd, cmd, arg)
        if isinstance(arg, int):
            return (await self.syscall(lib.SYS_fcntl, fd, cmd, arg))
        elif isinstance(arg, bytes):
            raise NotImplementedError
        else:
            raise Exception

    async def prctl_set_child_subreaper(self, flag: bool) -> None:
        logger.debug("prctl_set_child_subreaper(%s)", flag)
        # TODO also this guy
        prctl.set_child_subreaper(flag)

    async def faccessat(self, dirfd: int, pathname: bytes, mode: int, flags: int) -> None:
        logger.debug("faccessat(%s, %s, %s)", dirfd, pathname, mode)
        await self.syscall(lib.SYS_faccessat, dirfd, null_terminated(pathname), mode, flags)

    async def chdir(self, path: bytes) -> None:
        logger.debug("chdir(%s)", path)
        await self.syscall(lib.SYS_chdir, null_terminated(path))

    async def fchdir(self, fd: int) -> None:
        logger.debug("fchdir(%s)", fd)
        await self.syscall(lib.SYS_fchdir, fd)

    async def mkdirat(self, dirfd: int, pathname: bytes, mode: int) -> None:
        logger.debug("mkdirat(%s, %s, %s)", dirfd, pathname, mode)
        await self.syscall(lib.SYS_mkdirat, dirfd, null_terminated(pathname), mode)

    async def openat(self, dirfd: int, pathname: bytes, flags: int, mode: int) -> int:
        logger.debug("openat(%s, %s, %s, %s)", dirfd, pathname, flags, mode)
        ret = await self.syscall(lib.SYS_openat, dirfd, null_terminated(pathname), flags, mode)
        return ret

    async def getdents(self, fd: int, count: int) -> t.List[Dirent]:
        logger.debug("getdents64(%s, %s)", fd, count)
        buf = ffi.new('char[]', count)
        ret = await self.syscall(lib.SYS_getdents64, fd, buf, count)
        return rsyscall.stat.getdents64_parse(ffi.buffer(buf, ret))

    async def lseek(self, fd: int, offset: int, whence: int) -> int:
        logger.debug("lseek(%s, %s, %s)", fd, offset, whence)
        return (await self.syscall(lib.SYS_lseek, fd, offset, whence))

    async def unlinkat(self, dirfd: int, pathname: bytes, flags: int) -> None:
        logger.debug("unlinkat(%s, %s, %s)", dirfd, pathname, flags)
        await self.syscall(lib.SYS_unlinkat, dirfd, null_terminated(pathname), flags)

    async def linkat(self, olddirfd: int, oldpath: bytes, newdirfd: int, newpath: bytes, flags: int) -> None:
        logger.debug("linkat(%s, %s, %s, %s, %s)", olddirfd, oldpath, newdirfd, newpath, flags)
        await self.syscall(lib.SYS_linkat, olddirfd, null_terminated(oldpath), newdirfd, null_terminated(newpath), flags)

    async def symlinkat(self, target: bytes, newdirfd: int, newpath: bytes) -> None:
        logger.debug("symlinkat(%s, %s, %s)", target, newdirfd, newpath)
        await self.syscall(lib.SYS_symlinkat, null_terminated(target), newdirfd, newpath)

    async def readlinkat(self, dirfd: int, pathname: bytes, bufsiz: int) -> bytes:
        logger.debug("readlinkat(%s, %s, %s)", dirfd, pathname, bufsiz)
        buf = ffi.new('char[]', bufsiz)
        await self.syscall(lib.SYS_readlinkat, dirfd, null_terminated(pathname), bufsiz)
        return ffi.buffer(bufsiz)

    async def waitid(self, idtype: IdType, id: int, options: int, *, want_child_event: bool, want_rusage: bool
    ) -> t.Tuple[int, t.Optional[bytes], t.Optional[bytes]]:
        logger.debug("waitid(%s, %s, %s, want_child_event=%s, want_rusage=%s)", idtype, id, options, want_child_event, want_rusage)
        if want_child_event:
            siginfo = ffi.new('siginfo_t*')
        else:
            siginfo = ffi.NULL
        if want_rusage:
            rusage = ffi.new('struct rusage*')
        else:
            rusage = ffi.NULL
        ret = await self.syscall(lib.SYS_waitid, idtype, id, siginfo, options, rusage)
        return ret, bytes(ffi.buffer(siginfo)) if siginfo else None, bytes(ffi.buffer(rusage)) if rusage else None

    async def signalfd(self, fd: int, mask: t.Set[signal.Signals], flags: int) -> int:
        logger.debug("signalfd(%s, %s, %s)", fd, mask, flags)
        # sigset_t is just a 64bit bitmask of signals, I don't need the manipulation macros.
        set_integer = 0
        for sig in mask:
            set_integer |= 1 << (sig-1)
        set_data = ffi.new('unsigned long*', set_integer)
        return (await self.syscall(lib.SYS_signalfd4, fd, set_data, ffi.sizeof('unsigned long'), flags))

    async def rt_sigprocmask(self, how: SigprocmaskHow, set: t.Optional[t.Set[signal.Signals]]) -> t.Set[signal.Signals]:
        logger.debug("rt_sigprocmask(%s, %s)", how, set)
        old_set = ffi.new('unsigned long*')
        if set is None:
            await self.syscall(lib.SYS_rt_sigprocmask, how, ffi.NULL, old_set, ffi.sizeof('unsigned long'))
        else:
            set_integer = 0
            for sig in set:
                set_integer |= 1 << (sig-1)
            new_set = ffi.new('unsigned long*', set_integer)
            await self.syscall(lib.SYS_rt_sigprocmask, how, new_set, old_set, ffi.sizeof('unsigned long'))
        return {signal.Signals(bit) for bit in bits(old_set[0])}

    async def bind(self, sockfd: int, addr: bytes) -> None:
        logger.debug("bind(%s, %s)", sockfd, addr)
        await self.syscall(lib.SYS_bind, sockfd, ffi.from_buffer(addr), len(addr))

    async def listen(self, sockfd: int, backlog: int) -> None:
        logger.debug("listen(%s, %s)", sockfd, backlog)
        await self.syscall(lib.SYS_listen, sockfd, backlog)

    async def connect(self, sockfd: int, addr: bytes) -> None:
        logger.debug("connect(%s, %s)", sockfd, addr)
        await self.syscall(lib.SYS_connect, sockfd, ffi.from_buffer(addr), len(addr))

    async def accept(self, sockfd: int, addrlen: int, flags: int) -> t.Tuple[int, bytes]:
        logger.debug("accept(%s, %s, %s)", sockfd, addrlen, flags)
        buf = ffi.new('char[]', addrlen)
        lenbuf = ffi.new('size_t*', addrlen)
        fd = await self.syscall(lib.SYS_accept4, sockfd, buf, lenbuf, flags)
        return fd, bytes(ffi.buffer(buf, lenbuf[0]))

    async def socket(self, domain: int, type: int, protocol: int) -> int:
        logger.debug("socket(%s, %s, %s)", domain, type, protocol)
        return (await self.syscall(lib.SYS_socket, domain, type, protocol))

    async def socketpair(self, domain: int, type: int, protocol: int) -> t.Tuple[int, int]:
        logger.debug("socketpair(%s, %s, %s)", domain, type, protocol)
        sv = ffi.new('int[2]')
        await self.syscall(lib.SYS_socketpair, domain, type, protocol, sv)
        return (sv[0], sv[1])

    async def getsockopt(self, sockfd: int, level: int, optname: int, optlen: int) -> bytes:
        logger.debug("getsockopt(%s, %s, %s, %s)", sockfd, level, optname, optlen)
        buf = ffi.new('char[]', optlen)
        lenbuf = ffi.new('size_t*', optlen)
        # some custom netfilter socket options could return an actual value, according to getsockopt(2).
        # if that ever matters for anyone, we should change this to return a Tuple[int, bytes].
        await self.syscall(lib.SYS_getsockopt, sockfd, level, optname, buf, lenbuf)
        return bytes(ffi.buffer(buf, lenbuf[0]))

    async def setsockopt(self, sockfd: int, level: int, optname: int, optval: t.Optional[bytes], *, optlen: t.Optional[int]=None) -> None:
        logger.debug("setsockopt(%s, %s, %s, %s)", sockfd, level, optname, optval)
        if optval is None:
            # AF_ALG has some stupid API where to set an option to "val", it wants you to call with
            # optval=NULL and optlen=val.  so we have to contort ourselves to make that possible.
            if optlen == None:
                raise ValueError("if optvatl is None, optlen must be passed")
            buf = ffi.NULL
            length = optlen
        else:
            buf = ffi.from_buffer(optval)
            length = len(optval)
        await self.syscall(lib.SYS_setsockopt, sockfd, level, optname, buf, length)

    async def kill(self, pid: int, sig: signal.Signals) -> None:
        logger.debug("kill(%s, %s)", pid, sig)
        await self.syscall(lib.SYS_kill, pid, sig)

class FDNamespace:
    pass

class MemoryNamespace:
    def null(self) -> 'Pointer':
        return Pointer(None, 0) # type: ignore

class MountNamespace:
    pass

class FSInformation:
    "Filesystem root, current working directory, and umask; controlled by CLONE_FS."
    pass

class SignalMask:
    mask: t.Set[signal.Signals]
    def __init__(self):
        self.mask = set()

    def _validate(self, task: 'Task') -> SyscallInterface:
        if task.sigmask != self:
            raise Exception
        return task.syscall

    async def block(self, task: 'Task', mask: t.Set[signal.Signals]) -> None:
        syscall = self._validate(task)
        old_mask = await syscall.rt_sigprocmask(SigprocmaskHow.BLOCK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync?")
        self.mask = self.mask.union(mask)

    async def unblock(self, task: 'Task', mask: t.Set[signal.Signals]) -> None:
        syscall = self._validate(task)
        old_mask = await syscall.rt_sigprocmask(SigprocmaskHow.UNBLOCK, mask)
        if self.mask != old_mask:
            raise Exception("SignalMask tracking got out of sync?")
        self.mask = self.mask - mask

class Task:
    def __init__(self, syscall: SyscallInterface,
                 fd_namespace: FDNamespace,
                 memory: MemoryNamespace,
                 mount: MountNamespace,
                 fs: FSInformation,
    ) -> None:
        self.syscall = syscall
        self.memory = memory
        self.fd_namespace = fd_namespace
        self.mount = mount
        self.fs = fs
        self.sigmask = SignalMask()

class ProcessContext:
    """A Linux process with associated resources.

    Resources chiefly include memory and file descriptors. Maybe other
    things at some point.

    Eventually, when we support pipelining file descriptor creation, we'll need some
    kind of transactional interface, or a list of "pending" fds.

    This also contains a fixed SyscallInterface that is used to access this process.
    """
    def __init__(self, syscall_interface: SyscallInterface) -> None:
        self.syscall = syscall_interface

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

    async def set_nonblock(self, fd: 'FileDescriptor[File]') -> None:
        if self.shared:
            raise Exception("file object is shared and can't be mutated")
        await fd.syscall.fcntl(fd.number, fcntl.F_SETFL, os.O_NONBLOCK)

T_file = t.TypeVar('T_file', bound=File)
T_file_co = t.TypeVar('T_file_co', bound=File, covariant=True)

class ReadableFile(File):
    async def read(self, fd: 'FileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        return (await fd.syscall.read(fd.number, count))

class WritableFile(File):
    async def write(self, fd: 'FileDescriptor[WritableFile]', buf: bytes) -> int:
        return (await fd.syscall.write(fd.number, buf))

class SeekableFile(File):
    async def lseek(self, fd: 'FileDescriptor[SeekableFile]', offset: int, whence: int) -> int:
        return (await fd.syscall.lseek(fd.number, offset, whence))

class ReadableWritableFile(ReadableFile, WritableFile):
    pass

class SignalFile(ReadableFile):
    def __init__(self, mask: t.Set[signal.Signals], shared=False) -> None:
        super().__init__(shared=shared)
        self.mask = mask

    async def signalfd(self, fd: 'FileDescriptor[SignalFile]', mask: t.Set[signal.Signals]) -> None:
        await fd.syscall.signalfd(fd.number, mask, 0)
        self.mask = mask

class DirectoryFile(SeekableFile):
    # this is a fallback if we need to serialize this dirfd out
    raw_path: bytes
    def __init__(self, raw_path: bytes) -> None:
        self.raw_path = raw_path

    async def getdents(self, fd: 'FileDescriptor[DirectoryFile]', count: int) -> t.List[Dirent]:
        return (await fd.syscall.getdents(fd.number, count))

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
        struct = ffi.cast('struct sockaddr_un*', buf)
        if len(data) <= header:
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

class IPv4Address(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_in')
    port: int
    addr: bytes
    def __init__(self, port: int, addr: bytes) -> None:
        self.port = port
        self.addr = addr

    T = t.TypeVar('T', bound='IPv4Address')
    @classmethod
    def parse(cls: t.Type[T], data: bytes) -> T:
        buf = ffi.from_buffer(data)
        struct = ffi.cast('struct sockaddr_in*', buf)
        raise NotImplementedError
        # TODO need to swap byte order
        return cls(struct.sin_port, bytes(ffi.buffer(struct.sin_addr)))

    def to_bytes(self) -> bytes:
        raise NotImplementedError
        # TODO need to swap byte order
        addr = ffi.new('struct sockaddr_in*', (lib.AF_INET, self.port))
        return bytes(ffi.buffer(addr))

class SocketFile(t.Generic[T_addr], ReadableWritableFile):
    address_type: t.Type[T_addr]

    async def bind(self, fd: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await fd.syscall.bind(fd.number, addr.to_bytes())

    async def listen(self, fd: 'FileDescriptor[SocketFile]', backlog: int) -> None:
        await fd.syscall.listen(fd.number, backlog)

    async def connect(self, fd: 'FileDescriptor[SocketFile[T_addr]]', addr: T_addr) -> None:
        await fd.syscall.connect(fd.number, addr.to_bytes())

    async def getsockname(self, fd: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        data = await fd.syscall.getsockname(fd.number, self.address_type.addrlen)
        return self.address_type.parse(data)

    async def getpeername(self, fd: 'FileDescriptor[SocketFile[T_addr]]') -> T_addr:
        data = await fd.syscall.getpeername(fd.number, self.address_type.addrlen)
        return self.address_type.parse(data)

    async def getsockopt(self, fd: 'FileDescriptor[SocketFile[T_addr]]', level: int, optname: int, optlen: int) -> bytes:
        return (await fd.syscall.getsockopt(fd.number, level, optname, optlen))

    async def setsockopt(self, fd: 'FileDescriptor[SocketFile[T_addr]]', level: int, optname: int, optval: t.Optional[bytes],
                         *, optlen: t.Optional[int]=None) -> None:
        return (await fd.syscall.setsockopt(fd.number, level, optname, optval, optlen=optlen))

    async def accept(self, fd: 'FileDescriptor[SocketFile[T_addr]]', flags: int) -> t.Tuple['FileDescriptor[SocketFile[T_addr]]', T_addr]:
        fdnum, data = await fd.syscall.accept(fd.number, self.address_type.addrlen, flags)
        addr = self.address_type.parse(data)
        fd = FileDescriptor(type(self)(), fd.task, fd.fd_namespace, fdnum)
        return fd, addr

class UnixSocketFile(SocketFile[UnixAddress]):
    address_type = UnixAddress

class IPv4SocketFile(SocketFile[IPv4Address]):
    address_type = IPv4Address

class FileDescriptor(t.Generic[T_file_co]):
    "A file descriptor."
    file: T_file_co
    task: Task
    fd_namespace: FDNamespace
    number: int
    def __init__(self, file: T_file_co, task: Task, fd_namespace: FDNamespace, number: int) -> None:
        self.file = file
        self.task = task
        self.fd_namespace = fd_namespace
        self.number = number
        self.open = True

    @property
    def syscall(self) -> SyscallInterface:
        if self.task.fd_namespace != self.fd_namespace:
            raise Exception("Can't call syscalls on FD when my Task has moved out of my FDNamespaces")
        return self.task.syscall

    async def aclose(self):
        if self.open:
            await self.syscall.close(self.number)
            self.open = False
        else:
            pass

    def __str__(self) -> str:
        return f'FD({self.number}, {self.file}, {self.task})'

    async def __aenter__(self) -> 'FileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    def release(self) -> 'FileDescriptor[T_file_co]':
        """Disassociate the file descriptor from this object

        """
        if self.open:
            self.open = False
            return self.__class__(self.file, self.task, self.fd_namespace, self.number)
        else:
            raise Exception("file descriptor already closed")

    async def dup2(self, target: 'FileDescriptor') -> 'FileDescriptor[T_file_co]':
        """Make a copy of this file descriptor at target.number

        """
        if self.fd_namespace != target.fd_namespace:
            raise Exception("two fds are not in the same FDNamespace")
        if self is target:
            return self
        await self.syscall.dup2(self.number, target.number)
        target.open = False
        new_fd = type(self)(self.file, self.task, self.fd_namespace, target.number)
        # dup2 unsets cloexec on the new copy, so:
        self.file.shared = True
        return new_fd

    async def enable_cloexec(self) -> None:
        self.file.shared = True
        raise NotImplementedError

    async def disable_cloexec(self) -> None:
        raise NotImplementedError

    # These are just helper methods which forward to the method on the underlying file object.
    async def set_nonblock(self: 'FileDescriptor[File]') -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        await self.file.set_nonblock(self)

    async def read(self: 'FileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        return (await self.file.read(self, count))

    async def write(self: 'FileDescriptor[WritableFile]', buf: bytes) -> int:
        return (await self.file.write(self, buf))

    async def add(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.add(self, fd, event)

    async def modify(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.modify(self, fd, event)

    async def delete(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor') -> None:
        await self.file.delete(self, fd)

    async def wait(self: 'FileDescriptor[EpollFile]', maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await self.file.wait(self, maxevents, timeout))

    async def getdents(self: 'FileDescriptor[DirectoryFile]', count: int=4096) -> t.List[Dirent]:
        return (await self.file.getdents(self, count))

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

    async def wait_readable(self) -> None:
        return (await self.syscall.wait_readable(self.number))

async def allocate_unix_socket(task: Task, type: socket.SocketKind, protocol: int=0) -> FileDescriptor[UnixSocketFile]:
    sockfd = await task.syscall.socket(lib.AF_UNIX, type, protocol)
    return FileDescriptor(UnixSocketFile(), task, task.fd_namespace, sockfd)

class EpollFile(File):
    async def add(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_add(epfd.number, fd.number, event)

    async def modify(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_mod(epfd.number, fd.number, event)

    async def delete(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor) -> None:
        await epfd.syscall.epoll_ctl_del(epfd.number, fd.number)

    async def wait(self, epfd: FileDescriptor['EpollFile'], maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await epfd.syscall.epoll_wait(epfd.number, maxevents, timeout))

async def allocate_epoll(task: Task) -> FileDescriptor[EpollFile]:
    epfd = await task.syscall.epoll_create(EPOLL_CLOEXEC)
    return FileDescriptor(EpollFile(), task, task.fd_namespace, epfd)

class EpolledFileDescriptor(t.Generic[T_file_co]):
    epoller: 'Epoller'
    underlying: FileDescriptor[T_file_co]
    queue: trio.hazmat.UnboundedQueue
    def __init__(self, epoller: 'Epoller', underlying: FileDescriptor[T_file_co], queue: trio.hazmat.UnboundedQueue) -> None:
        self.epoller = epoller
        self.underlying = underlying
        self.queue = queue
        self.in_epollfd = True

    async def modify(self, events: EpollEventMask) -> None:
        await self.epoller.epfd.modify(self.underlying, EpollEvent(self.underlying.number, events))

    async def wait(self) -> t.List[EpollEvent]:
        while True:
            try:
                return self.queue.get_batch_nowait()
            except trio.WouldBlock:
                await self.epoller.do_wait()

    async def aclose(self) -> None:
        if self.in_epollfd:
            await self.epoller.epfd.delete(self.underlying)
            self.in_epollfd = False
        await self.underlying.aclose()

    async def __aenter__(self) -> 'EpolledFileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

class Epoller:
    def __init__(self, epfd: FileDescriptor[EpollFile]) -> None:
        self.epfd = epfd
        self.fd_map: t.Dict[int, EpolledFileDescriptor] = {}
        self.running_wait: t.Optional[trio.Event] = None

    async def add(self, fd: FileDescriptor[T_file], events: EpollEventMask=None
    ) -> EpolledFileDescriptor:
        if events is None:
            events = EpollEventMask.make()
        fd = fd.release()
        queue = trio.hazmat.UnboundedQueue()
        wrapper = EpolledFileDescriptor(self, fd, queue)
        self.fd_map[fd.number] = wrapper
        await self.epfd.add(fd, EpollEvent(fd.number, events))
        return wrapper

    async def do_wait(self) -> None:
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait

            # we first epoll_wait optimistically, and only then wait_readable
            received_events = await self.epfd.wait(maxevents=32, timeout=-1)
            if len(received_events) == 0:
                await self.epfd.wait_readable()
                received_events = await self.epfd.wait(maxevents=32, timeout=-1)
            for event in received_events:
                queue = self.fd_map[event.data].queue
                queue.put_nowait(event.events)

            self.running_wait = None
            running_wait.set()

    async def aclose(self) -> None:
        await self.epfd.aclose()

    async def __aenter__(self) -> 'Epoller':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()


class AsyncFileDescriptor(t.Generic[T_file_co]):
    epolled: EpolledFileDescriptor[T_file_co]

    @staticmethod
    async def make(epoller: Epoller, fd: FileDescriptor[T_file]) -> 'AsyncFileDescriptor[T_file]':
        await fd.set_nonblock()
        epolled = await epoller.add(fd, EpollEventMask.make(
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
                return (await self.epolled.underlying.read())
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
                err = ffi.cast('int*', ffi.from_buffer(retbuf))
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

class MemoryMapping:
    task: Task
    address: int
    length: int

    @property
    def syscall(self) -> SyscallInterface:
        # A task can't change address space, so this will always be a
        # valid SyscallInterface for operating on this mapping.
        return self.task.syscall

    def __init__(self,
                 task: Task,
                 address: int,
                 length: int,
    ) -> None:
        self.task = task
        self.address = address
        self.length = length

    def in_bounds(self, ptr: int, length: int) -> bool:
        if ptr < self.address:
            return False
        offset = self.address - ptr
        if (self.length - offset) < length:
            return False
        return True

    async def write(self, ptr: int, data: bytes) -> None:
        if not self.in_bounds(ptr, len(data)):
            raise Exception("pointer and data not in bounds of mapping")
        logger.debug("writing to memory %s data %s", hex(ptr), data)
        lib.memcpy(ffi.cast('void*', ptr), ffi.from_buffer(data), len(data))

    async def read(self, ptr: int, size: int) -> bytes:
        if not self.in_bounds(ptr, size):
            raise Exception("pointer and size not in bounds of mapping")
        return bytes(ffi.buffer(ffi.cast('void*', ptr), size))

    async def unmap(self) -> None:
        await self.syscall.munmap(self.address, self.length)

    async def __aenter__(self) -> 'MemoryMapping':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.unmap()

class Pointer:
    mapping: MemoryMapping
    address: int
    def __init__(self, mapping: MemoryMapping, address: int) -> None:
        self.mapping = mapping
        self.address = address

    async def write(self, data: bytes) -> None:
        await self.mapping.write(self.address, data)

    async def read(self, size: int) -> bytes:
        return (await self.mapping.read(self.address, size))

    def __add__(self, other: int) -> 'Pointer':
        return Pointer(self.mapping, self.address + other)

    def __sub__(self, other: int) -> 'Pointer':
        return Pointer(self.mapping, self.address - other)

class Stack:
    def __init__(self, allocation_pointer: Pointer) -> None:
        self.allocation_pointer = allocation_pointer

    def alloc(self, size: int) -> Pointer:
        self.allocation_pointer -= size
        return self.allocation_pointer

    def align(self):
        self.allocation_pointer -= self.allocation_pointer.address % 16

    async def push(self, data: bytes) -> Pointer:
        memory = self.alloc(len(data))
        await memory.write(data)
        return memory

async def allocate_memory(task: Task, size: int=4096) -> MemoryMapping:
    size = 4096
    # it seems like MAP_GROWSDOWN does nothing, otherwise I would be using it...
    ret = await task.syscall.mmap(0, size, lib.PROT_READ|lib.PROT_WRITE,
                                  lib.MAP_PRIVATE|lib.MAP_ANONYMOUS,
                                  -1, 0)
    return MemoryMapping(task, ret, size)

class PathBase:
    """These are possible bases for Paths.

    A path can be interpreted relative to three different things:
    - A directory file descriptor
    - The task's root directory
    - The task's current working directory

    The latter two can change location, both by chdir and chroot, and
    by changing mount namespace.

    """
    @abc.abstractproperty
    def dirfd_num(self) -> int: ...
    @abc.abstractproperty
    def path_prefix(self) -> bytes: ...
    @abc.abstractproperty
    def task(self) -> Task: ...

class DirfdPathBase(PathBase):
    dirfd: FileDescriptor[DirectoryFile]
    def __init__(self, dirfd: FileDescriptor[DirectoryFile]) -> None:
        self.dirfd = dirfd
    @property
    def dirfd_num(self) -> int:
        return self.dirfd.number
    @property
    def path_prefix(self) -> bytes:
        return b""
    @property
    def task(self) -> Task:
        if self.dirfd.task.fd_namespace != self.dirfd.fd_namespace:
            raise Exception("Can't call syscalls on dirfd when my Task has moved out of my FDNamespaces")
        return self.dirfd.task

    def __str__(self) -> str:
        return f"Dirfd({self.dirfd.number})"

class RootPathBase(PathBase):
    def __init__(self, task: Task) -> None:
        self._task = task
    @property
    def dirfd_num(self) -> int:
        return sfork.AT_FDCWD
    @property
    def path_prefix(self) -> bytes:
        return b"/"
    @property
    def task(self) -> Task:
        return self._task
    def __str__(self) -> str:
        return "[ROOT]"

class CurrentWorkingDirectoryPathBase(PathBase):
    task: Task
    def __init__(self, task: Task) -> None:
        self._task = task
    @property
    def dirfd_num(self) -> int:
        return sfork.AT_FDCWD
    @property
    def path_prefix(self) -> bytes:
        return b""
    @property
    def task(self) -> Task:
        return self._task
    def __str__(self) -> str:
        return "[CWD]"

class Path:
    "This is our entry point to any syscall that takes a path argument."
    base: PathBase
    path: bytes
    def __init__(self, base: PathBase, path: t.Union[str, bytes]) -> None:
        self.base = base
        self.path = sfork.to_bytes(path)
        if len(self.path) == 0:
            # readlink, and possibly other syscalls, behave differently when given an empty path and a dirfd
            # in general an empty path is probably not good
            raise Exception("empty paths not allowed")

    @staticmethod
    def from_bytes(task: Task, path: bytes) -> 'Path':
        if path.startswith(b"/"):
            return Path(RootPathBase(task), path[1:])
        else:
            return Path(CurrentWorkingDirectoryPathBase(task), path)

    @property
    def _full_path(self) -> bytes:
        return self.base.path_prefix + self.path

    @property
    def _raw_path(self) -> bytes:
        if isinstance(self.base, DirfdPathBase):
            return self.base.dirfd.file.raw_path + b"/" + self.path
        else:
            return self._full_path
    @property
    def _proc_path(self) -> bytes:
        """The path, using /proc to do dirfd-relative lookups

        This is not too portable - there are many situations where
        /proc might not be mounted. But it's the only recourse for a
        few syscalls which don't have *at versions.

        """
        if isinstance(self.base, DirfdPathBase):
            return b"/proc/self/fd/" + str(self.base.dirfd.number).encode() + b"/" + self.path
        else:
            return self._full_path

    @property
    def syscall(self) -> SyscallInterface:
        return self.base.task.syscall

    def assert_okay_for_task(self, task: Task) -> None:
        if isinstance(self.base, DirfdPathBase):
            if self.base.dirfd.task is not task:
                raise Exception("can't use a Path based on a dirfd not in my task")
        elif isinstance(self.base, RootPathBase):
            if self.base.task.fs != task.fs:
                raise Exception("can't use a Path based on a different root directory")
        elif isinstance(self.base, CurrentWorkingDirectoryPathBase):
            if self.base.task.fs != task.fs:
                raise Exception("can't use a Path based on a different current working directory")

    async def mkdir(self, mode=0o777) -> 'Path':
        await self.syscall.mkdirat(self.base.dirfd_num, self._full_path, mode)
        return self

    async def chdir(self) -> None:
        "Mutate the underlying task under this Path, changing its CWD to something new."
        if isinstance(self.base, DirfdPathBase):
            await self.syscall.fchdir(self.base.dirfd.number)
            await self.syscall.chdir(self.path)
        else:
            await self.syscall.chdir(self._full_path)

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
            file = DirectoryFile(self._raw_path)
        else:
            # os.O_RDONLY is 0, so if we don't have any of the rest, then...
            file = ReadableFile()
        # hmm hmmm we need a task I guess, not just a syscall
        # so we can find the files
        fd_namespace = self.base.task.fd_namespace
        fd = await self.syscall.openat(self.base.dirfd_num, self._full_path, flags, mode)
        return FileDescriptor(file, self.base.task, fd_namespace, fd)

    async def creat(self, mode=0o644) -> FileDescriptor[WritableFile]:
        file = WritableFile()
        fd_namespace = self.base.task.fd_namespace
        fd = await self.syscall.openat(self.base.dirfd_num, self._full_path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, mode)
        return FileDescriptor(file, self.base.task, fd_namespace, fd)

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
            await self.syscall.faccessat(self.base.dirfd_num, self._full_path, mode, 0)
            return True
        except OSError:
            return False

    async def unlink(self, flags: int=0) -> None:
        await self.syscall.unlinkat(self.base.dirfd_num, self._full_path, flags)

    async def rmdir(self) -> None:
        await self.syscall.unlinkat(self.base.dirfd_num, self._full_path, rsyscall.stat.AT_REMOVEDIR)

    async def link_to(self, oldpath: 'Path', flags: int=0) -> 'Path':
        "Create a hardlink at Path 'self' to the file at Path 'oldpath'"
        await self.syscall.linkat(oldpath.base.dirfd_num, oldpath._full_path,
                                  self.base.dirfd_num, self._full_path,
                                  flags)
        return self

    async def symlink_to(self, target: bytes) -> 'Path':
        "Create a symlink at Path 'self' pointing to the passed-in target"
        await self.syscall.symlinkat(target, self.base.dirfd_num, self._full_path)
        return self

    async def readlink(self, bufsiz: int=4096) -> bytes:
        return (await self.syscall.readlinkat(self.base.dirfd_num, self._full_path, bufsiz))

    def unix_address(self) -> UnixAddress:
        """Return an address that can be used with bind/connect for Unix sockets

        Linux doesn't support bindat/connectat or similar, so this is emulated with /proc.

        This will fail if the bytes component of the path is too long,
        because bind has a limit of 108 bytes for the pathname.

        """
        return UnixAddress(self._proc_path)

    def __truediv__(self, path_element: t.Union[str, bytes]) -> 'Path':
        element: bytes = sfork.to_bytes(path_element)
        if b"/" in element:
            raise Exception("no / allowed in path elements, do it one by one")
        if self.path == b'.':
            # if the path is empty, just be relative
            return Path(self.base, element)
        else:
            return Path(self.base, self.path + b"/" + element)

    def __str__(self) -> str:
        return f"Path({self.base}, {self.path})"

class StandardStreams:
    stdin: FileDescriptor[ReadableFile]
    stdout: FileDescriptor[WritableFile]
    stderr: FileDescriptor[WritableFile]

    def __init__(self,
                 stdin: FileDescriptor[ReadableFile],
                 stdout: FileDescriptor[WritableFile],
                 stderr: FileDescriptor[WritableFile]) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

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
    def __init__(self,
                 task: Task,
                 argv: t.List[bytes],
                 environ: t.Mapping[bytes, bytes],
                 stdstreams: StandardStreams) -> None:
        self.task = task
        self.argv = argv
        self.environ = environ
        self.stdstreams = stdstreams

def wrap_stdin_out_err(task: Task) -> StandardStreams:
    stdin = FileDescriptor(ReadableFile(shared=True), task, task.fd_namespace, 0)
    stdout = FileDescriptor(WritableFile(shared=True), task, task.fd_namespace, 1)
    stderr = FileDescriptor(WritableFile(shared=True), task, task.fd_namespace, 2)
    return StandardStreams(stdin, stdout, stderr)

def gather_local_bootstrap() -> UnixBootstrap:
    task = Task(LocalSyscall(trio.hazmat.wait_readable, direct_syscall),
                FDNamespace(), MemoryNamespace(), MountNamespace(), FSInformation())
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
        basename: bytes = sfork.to_bytes(name)
        if basename in self.cache:
            return self.cache[basename]
        else:
            result = await self.uncached_lookup(basename)
            if result is None:
                raise Exception(f"couldn't find {name}")
            # we don't cache negative lookups
            self.cache[basename] = result
            return result

class UnixUtilities:
    rm: Path
    sh: Path
    def __init__(self, rm: Path, sh: Path) -> None:
        self.rm = rm
        self.sh = sh

async def build_unix_utilities(exec_cache: ExecutableLookupCache) -> UnixUtilities:
    rm = await exec_cache.lookup("rm")
    sh = await exec_cache.lookup("sh")
    return UnixUtilities(rm=rm, sh=sh)

class UnixEnvironment:
    """The utilities provided by a standard Unix userspace.

    These are primarily built from various environment variables.

    """
    # various things picked up by environment variables
    executable_lookup_cache: ExecutableLookupCache
    tmpdir: Path
    # utilities are eagerly looked up in PATH
    utilities: UnixUtilities
    # locale?
    # home directory?
    def __init__(self,
                 executable_lookup_cache: ExecutableLookupCache,
                 tmpdir: Path,
                 utilities: UnixUtilities,
    ) -> None:
        self.executable_lookup_cache = executable_lookup_cache
        self.tmpdir = tmpdir
        self.utilities = utilities

async def build_unix_environment(bootstrap: UnixBootstrap) -> UnixEnvironment:
    executable_dirs: t.List[Path] = []
    for prefix in bootstrap.environ[b"PATH"].split(b":"):
        executable_dirs.append(Path.from_bytes(bootstrap.task, prefix))
    executable_lookup_cache = ExecutableLookupCache(executable_dirs)
    tmpdir = Path.from_bytes(bootstrap.task, bootstrap.environ[b"TMPDIR"])
    utilities = await build_unix_utilities(executable_lookup_cache)
    return UnixEnvironment(
        executable_lookup_cache=executable_lookup_cache,
        tmpdir=tmpdir,
        utilities=utilities,
    )

async def spit(path: Path, text: t.Union[str, bytes]) -> Path:
    """Open a file, creating and truncating it, and write the passed text to it

    Probably shouldn't use this on FIFOs or anything.

    Returns the passed-in Path so this serves as a nice pseudo-constructor.

    """
    data = sfork.to_bytes(text)
    async with (await path.creat()) as fd:
        while len(data) > 0:
            ret = await fd.write(data)
            data = data[ret:]
    return path

@asynccontextmanager
async def mkdtemp(root: Path, rm_location: Path, prefix: str="mkdtemp"
) -> t.AsyncGenerator[t.Tuple[FileDescriptor[DirectoryFile], Path], None]:
    random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    basename = prefix+"."+random_suffix
    path = root/basename
    await path.mkdir(mode=0o700)
    async with (await path.open(os.O_DIRECTORY)) as dirfd:
        yield dirfd, Path(DirfdPathBase(dirfd), b".")
        async with subprocess(root.base.task) as rm_proc:
            # TODO hmm I think I will unshare the CLONE_FS first before doing this
            # though I guess it does that by default
            await root.chdir()
            # TODO we should convert this to use supervise, and wait on it
            # wait no. we can skip that.
            # we should be able to wait on children natively.
            # that requires, eh, signalfd, and, eh...
            # yeah, just signalfd, right?
            # we get a signalfd,
            # then we loop on waitid,
            # and we dispatch events out to the children.
            # we don't necessarily need supervise for this.
            # possibly dispatch events out over a pipe?
            # childfd, loop wait, write each event to pipe?
            # and allow signaling only our children?
            # essentially implement the same logic as supervise?
            # the nice thing, though, with supervise, is that even if we terminate uncleanly,
            # it kills everything off.
            # how do we achieve that same behavior? we can't?
            # it's an unnecessary, weird feature.
            # if Linux properly had the ability to close the child group so nothing could escape,
            # and did the cleanup for me,
            # it would not be necessary.
            # but because it doesn't close the child group,
            # I can exploit that to have my supervise process outlive me, and clean up in response to me exiting.
            # given that, um...
            # well, anyway, we still want to be signal-safe, right?
            # so do we want to clean processes up manually?
            # what about the idea of a process which cleans up a temp directory when we exit?
            # hmm hmm this is all intriguing
            # wouldn't it still be good to implement the same pipe-of-child-events-in, signals-out thing as supervise?
            # the only issue is the autocleanup is missing.
            # so when my process dies, there's no safe way to kill my children, because they all get reparented to init
            # the autocleanup thus depends on keeping a separate process alive to provide that stuff.
            # the autocleanup is slow anyway...
            # I think implementing the event-driven in-process child process management thing is a good idea.
            # that will reduce my dependency on supervise and general weirdness...
            await rm_proc.exec(rm_location, ["rm", "-r", basename])

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

async def allocate_signalfd(task: Task, mask: t.Set[signal.Signals]) -> FileDescriptor[SignalFile]:
    sigfd_num = await task.syscall.signalfd(-1, mask, lib.SFD_CLOEXEC)
    return FileDescriptor(SignalFile(mask), task, task.fd_namespace, sigfd_num)

class SignalQueue:
    def __init__(self, signal_block: SignalBlock, sigfd: AsyncFileDescriptor[SignalFile]) -> None:
        self.signal_block = signal_block
        self.sigfd = sigfd

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

async def allocate_signalqueue(task: Task, epoller: Epoller, mask: t.Set[signal.Signals]) -> SignalQueue:
    signal_block = await SignalBlock.make(task, mask)
    sigfd = await allocate_signalfd(task, mask)
    async_sigfd = await AsyncFileDescriptor.make(epoller, sigfd)
    return SignalQueue(signal_block, async_sigfd)

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
    def __init__(self, pid: int, queue: trio.hazmat.UnboundedQueue,
                 monitor: 'ChildTaskMonitor') -> None:
        self.pid = pid
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

    async def send_signal(self, sig: signal.Signals) -> None:
        async with self as pid:
            if pid:
                await self.syscall.kill(pid, sig)
            else:
                raise Exception("child is already dead!")

    async def kill(self) -> None:
        async with self as pid:
            if pid:
                await self.syscall.kill(pid, signal.SIGKILL)

    async def __aenter__(self) -> t.Optional[int]:
        """Returns the pid for this child process, or None if it's already dead.

        Operating on the pid of a child process requires taking the wait_lock to make sure
        the process's zombie is not collected while we're using its pid.

        """
        # TODO this could really be a reader-writer lock, with this use as the reader and
        # wait as the writer.
        await self.monitor.wait_lock.acquire()
        self._flush_nowait()
        if self.death_event:
            return None
        return self.pid

    async def __aexit__(self, *args, **kwargs) -> None:
        self.monitor.wait_lock.release()

class ChildTaskMonitor:
    @staticmethod
    async def make(task: Task, epoller: Epoller) -> 'ChildTaskMonitor':
        signal_queue = await allocate_signalqueue(task, epoller, {signal.SIGCHLD})
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
        tid = await task.syscall.clone(flags, child_stack.address,
                                       ptid=0, ctid=ctid.address, newtls=newtls.address)
        child_task = ChildTask(tid, trio.hazmat.UnboundedQueue(), self)
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
                        _, siginfo, _ = await task.syscall.waitid(
                            IdType.ALL, 0, lib._WALL|lib.WEXITED|lib.WSTOPPED|lib.WCONTINUED|lib.WNOHANG,
                            want_child_event=True, want_rusage=False
                        )
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

class Function:
    "A function, with a memory address, in some address space."
    address: int
    memory: MemoryNamespace
    def __init__(self, address: int, memory: MemoryNamespace) -> None:
        self.address = address
        self.memory = memory

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
    futex_mapping: MemoryMapping
    def __init__(self, child_task: ChildTask, futex_task: ChildTask, futex_mapping: MemoryMapping) -> None:
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
    stack_mapping: MemoryMapping
    def __init__(self, thread: Thread, stack_mapping: MemoryMapping) -> None:
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

def build_trampoline_stack(function: Function, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> bytes:
    # TODO clean this up with dicts or tuples or something
    stack_struct = ffi.new('struct rsyscall_trampoline_stack*')
    stack_struct.rdi = arg1
    stack_struct.rsi = arg2
    stack_struct.rdx = arg3
    stack_struct.rcx = arg4
    stack_struct.r8  = arg5
    stack_struct.r9  = arg6
    stack_struct.function = ffi.cast('void*', function.address)
    trampoline_addr = int(ffi.cast('long', lib.rsyscall_trampoline))
    packed_trampoline_addr = struct.pack('Q', trampoline_addr)
    stack = packed_trampoline_addr + bytes(ffi.buffer(stack_struct))
    return stack

class ThreadMaker:
    def __init__(self, monitor: ChildTaskMonitor) -> None:
        self.monitor = monitor
        task = monitor.signal_queue.sigfd.epolled.underlying.task
        # TODO pull this function out of somewhere sensible
        self.futex_func = Function(ffi.cast('long', lib.rsyscall_futex_helper), task.memory)

    async def clone(self, flags: int, child_stack: Pointer, newtls: Pointer) -> Thread:
        """Provides an asynchronous interface to the CLONE_CHILD_CLEARTID functionality

        Executes the instruction "ret" immediately after cloning.

        """
        if not (flags & lib.CLONE_VM):
            # TODO let's figure out how to force the futex address to be shared memory with the
            # child, by mapping a memfd instead of using CLONE_PRIVATE 
            raise Exception("CLONE_VM is mandatory right now because I'm lazy")
        task = self.monitor.signal_queue.sigfd.epolled.underlying.task
        mapping = await allocate_memory(task)
        stack = Stack(Pointer(mapping, mapping.address + mapping.length))
        # allocate the futex at the base of the stack, with "1" written to it to match
        # what futex_helper expects
        futex_data = struct.pack('i', 1)
        # TODO huh, writing the stack seems be overwritting this
        futex_address = await stack.push(futex_data)
        # align the stack to a 16-bit boundary now, so after pushing the trampoline data,
        # which the trampoline will all pop off, the stack will be aligned.
        stack.align()
    
        # build the trampoline, push it on the stack, and start the thread
        trampoline_data = build_trampoline_stack(self.futex_func,
                                                 futex_address.address, 0, 0, 0, 0, 0)
        complete_stack = await stack.push(trampoline_data)
        # TODO maybe I can use CLONE_THREAD here? or at least more clone
        futex_task = await self.monitor.clone(
            lib.CLONE_VM|lib.CLONE_FILES|signal.SIGCHLD, complete_stack,
            ctid=task.memory.null(), newtls=task.memory.null())
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
            ctid=futex_address, newtls=newtls)
        return Thread(child_task, futex_task, mapping)

    async def make_cthread(self, flags: int,
                          function: Function, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0,
    ) -> CThread:
        task = self.monitor.signal_queue.sigfd.epolled.underlying.task
        mapping = await allocate_memory(task)
        stack = Stack(Pointer(mapping, mapping.address + mapping.length))
    
        trampoline_data = build_trampoline_stack(function, arg1, arg2, arg3, arg4, arg5, arg6)
        complete_stack = await stack.push(trampoline_data)
        # TODO actually allocate TLS
        tls = task.memory.null()
        thread = await self.clone(flags|signal.SIGCHLD, complete_stack, tls)
        return CThread(thread, mapping)

class RsyscallException(Exception):
    pass

class RsyscallHangup(Exception):
    pass

class RsyscallConnection:
    """A connection to some rsyscall server where we can make syscalls
    """
    tofd: AsyncFileDescriptor[WritableFile]
    fromfd: AsyncFileDescriptor[ReadableFile]
    def __init__(self,
                 tofd: AsyncFileDescriptor[WritableFile],
                 fromfd: AsyncFileDescriptor[ReadableFile]) -> None:
        self.tofd = tofd
        self.fromfd = fromfd

    async def close(self) -> None:
        await self.tofd.aclose()
        await self.fromfd.aclose()

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        # TODO we need to match up requests to responses so this method can be called concurrently
        request = ffi.new('struct rsyscall_syscall*',
                          (number,
                           (ffi.cast('long', arg1), ffi.cast('long', arg2), ffi.cast('long', arg3),
                            ffi.cast('long', arg4), ffi.cast('long', arg5), ffi.cast('long', arg6))))
        try:
            await self.tofd.write(bytes(ffi.buffer(request)))
            response_bytes = await self.fromfd.read(ffi.sizeof('unsigned long'))
        except OSError as e:
            # we raise a different exception so that users can distinguish syscall errors from
            # transport errors
            raise RsyscallException() from e
        # raise exception on hangup I guess?
        # and catch it in specific syscalls?
        # or, how else will I handle the fact that,
        # exit and exec don't expect a response?
        # or, rather, they expect a hup or a response
        # an optional response
        if len(response_bytes) == 0:
            raise RsyscallHangup()
        response, = struct.unpack('q', response_bytes)
        return response

    async def __aenter__(self) -> 'RsyscallConnection':
        return self

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()

class RsyscallInternals:
    def __init__(self, infd: FileDescriptor[ReadableFile], outfd: FileDescriptor[WritableFile]) -> None:
        self.infd = infd
        self.outfd = outfd

class RsyscallTask:
    def __init__(self,
                 thread: CThread,
                 connection: RsyscallConnection,
                 task: Task,
                 internals: RsyscallInternals,
    ) -> None:
        self.thread = thread
        self.connection = connection
        self.task = task
        self.internals = internals

    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> ChildTask:
        await self.task.syscall.execveat(dirfd, path, argv, envp, flags)
        # the connection is no longer needed
        await self.connection.close()
        # we return the still-running ChildTask that was inside this RsyscallTask
        return (await self.thread.wait_for_mm_release())

    async def execve(self, path: Path, argv: t.List[t.Union[str, bytes]], *, envp: t.Optional[t.Mapping[str, str]]=None) -> ChildTask:
        path.assert_okay_for_task(self.task)
        if envp is None:
            # TODO os.environ should actually be pulled from, er... somewhere
            envp = dict(**os.environ)
        await self.task.syscall.execveat(
            path.base.dirfd_num, path._full_path,
            [sfork.to_bytes(arg) for arg in argv],
            sfork.serialize_environ(**envp), flags=0)
        # the connection is no longer needed
        await self.connection.close()
        # we return the still-running ChildTask that was inside this RsyscallTask
        return (await self.thread.wait_for_mm_release())

    async def exit(self, status) -> None:
        await self.task.syscall.exit(0)
        await self.close()

    async def close(self) -> None:
        await self.thread.close()
        await self.connection.close()

    async def __aenter__(self) -> 'RsyscallTask':
        return self

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()

async def call_function(task: Task, stack: Stack, function: Function, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> ChildEvent:
    "Calls a C function and waits for it to complete. Returns the ChildEvent that the child thread terminated with."
    stack.align()
    complete_stack = await stack.push(build_trampoline_stack(function, arg1, arg2, arg3, arg4, arg5, arg6))
    # we directly spawn a thread for the function and wait on it
    pid = await task.syscall.clone(lib.CLONE_VM|lib.CLONE_FILES, complete_stack.address, ptid=0, ctid=0, newtls=0)
    _, siginfo, _ = await task.syscall.waitid(IdType.PID, pid, lib._WALL|lib.WEXITED, want_child_event=True, want_rusage=False)
    struct = ffi.cast('siginfo_t*', ffi.from_buffer(siginfo))
    child_event = ChildEvent.make(ChildCode(struct.si_code),
                                  pid=int(struct.si_pid), uid=int(struct.si_uid),
                                  status=int(struct.si_status))
    return child_event

async def do_cloexec_except(task: Task, excluded_fd_numbers: t.Set[int]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    function = Function(ffi.cast('long', lib.rsyscall_do_cloexec), task.memory)
    async with (await allocate_memory(task)) as mapping:
        stack = Stack(Pointer(mapping, mapping.address + mapping.length))
        fd_array = await stack.push(array.array('i', excluded_fd_numbers).tobytes())
        child_event = await call_function(task, stack, function, fd_array.address, len(excluded_fd_numbers))
        if not child_event.clean():
            raise Exception("cloexec function child died!", child_event)

class RsyscallSpawner:
    def __init__(self, task: Task, thread_maker: ThreadMaker, epoller: Epoller) -> None:
        self.task = task
        self.thread_maker = thread_maker
        self.epoller = epoller
        self.function = Function(ffi.cast('long', lib.rsyscall_server), task.memory)

    async def spawn(self, user_fds: t.List[FileDescriptor]) -> t.Tuple[RsyscallTask, t.List[FileDescriptor]]:
        for fd in user_fds:
            if fd.fd_namespace is not self.task.fd_namespace:
                raise Exception("can only translate file descriptors from my fd namespace")
        pipe_in = await allocate_pipe(self.task)
        pipe_out = await allocate_pipe(self.task)
        # new fd namespace is created here
        cthread = await self.thread_maker.make_cthread(
            lib.CLONE_VM|lib.CLONE_FS, self.function, pipe_in.rfd.number, pipe_out.wfd.number)

        async_tofd = await AsyncFileDescriptor.make(self.epoller, pipe_in.wfd)
        async_fromfd = await AsyncFileDescriptor.make(self.epoller, pipe_out.rfd)
        rsyscall_connection = RsyscallConnection(async_tofd, async_fromfd)

        new_task = Task(LocalSyscall(trio.hazmat.wait_readable, rsyscall_connection.syscall),
                        FDNamespace(), self.task.memory, self.task.mount, self.task.fs)

        inherited_fd_numbers: t.Set[int] = set()
        def translate(fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
            inherited_fd_numbers.add(fd.number)
            return FileDescriptor(fd.file, new_task, new_task.fd_namespace, fd.number)

        # pass a few file descriptors down to the new task
        internals = RsyscallInternals(translate(pipe_in.rfd), translate(pipe_out.wfd))
        await pipe_in.rfd.aclose()
        await pipe_out.wfd.aclose()
        inherited_user_fds = [translate(fd) for fd in user_fds]

        # close everything that's cloexec and not explicitly passed down
        await do_cloexec_except(new_task, inherited_fd_numbers)

        rsyscall_task = RsyscallTask(cthread, rsyscall_connection, new_task, internals)
        return rsyscall_task, inherited_user_fds


class Pipe:
    def __init__(self, rfd: FileDescriptor[ReadableFile],
                 wfd: FileDescriptor[WritableFile]) -> None:
        self.rfd = rfd
        self.wfd = wfd

    async def aclose(self):
        await self.rfd.aclose()
        await self.wfd.aclose()

    async def __aenter__(self) -> 'Pipe':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

async def allocate_pipe(task: Task) -> Pipe:
    r, w = await task.syscall.pipe()
    return Pipe(FileDescriptor(ReadableFile(shared=False), task, task.fd_namespace, r),
                FileDescriptor(WritableFile(shared=False), task, task.fd_namespace, w))

class SubprocessContext:
    def __init__(self, task: Task, child_files: FDNamespace, parent_files: FDNamespace) -> None:
        self.task = task
        self.child_files = child_files
        self.parent_files = parent_files
        self.pid: t.Optional[int] = None

    def translate(self, fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
        """Translate FDs from the parent's FDNamespace to the child's FDNamespace

        Any file descriptor created by my task in parent_files is now
        also present in child_files, so we're able to translate them
        to child_files.

        This only works for fds created by my task because fds from
        other tasks may have been created after the fork, through
        concurrent execution. To translate fds from other tasks,
        provide them as arguments at fork time.

        """
        if self.pid is not None:
            raise Exception("Already left the subprocess")
        if fd.fd_namespace != self.parent_files:
            raise Exception("Can't translate an fd not coming from my parent's FDNamespace")
        if fd.task != self.task:
            raise Exception("Can't translate an fd not coming from my Task; it could have been created after the fork.")
        return type(fd)(fd.file, fd.task, self.child_files, fd.number)

    @property
    def syscall(self) -> SyscallInterface:
        if self.pid is not None:
            raise Exception("Already left this process")
        return self.task.syscall

    async def exit(self, status: int) -> None:
        self.pid = await self.syscall.exit(status)
        self.task.fd_namespace = self.parent_files

    async def exec(self, path: Path, argv: t.List[t.Union[str, bytes]],
             *, envp: t.Optional[t.Mapping[str, str]]=None) -> None:
        if envp is None:
            # TODO os.environ should actually be pulled from, er... somewhere
            envp = dict(**os.environ)
        # this is too restrictive but whatever
        if path.base.task != self.task:
            raise Exception("can't exec a path from another task")
        self.pid = await path.execve(argv, envp) # type: ignore
        self.task.fd_namespace = self.parent_files

    async def fexec(self, fd: FileDescriptor, argv: t.List[t.Union[str, bytes]],
                    *, envp: t.Optional[t.Dict[str, str]]=None) -> None:
        if envp is None:
            envp = dict(**os.environ)
        # TODO this won't work for scripts since cloexec needs to be unset
        self.pid = await self.syscall.execveat(
            fd.number, b"",
            [sfork.to_bytes(arg) for arg in argv],
            sfork.serialize_environ(**envp), flags=rsyscall.epoll.AT_EMPTY_PATH)
        self.task.fd_namespace = self.parent_files

@asynccontextmanager
async def subprocess(task: Task) -> t.Any:
    # the way we are setting a variable to a new thing, then resetting
    # it back to an old thing, is really contextvar-ish. but it's
    # inside an explicitly passed around object. but it's still the
    # same kind of behavior. by what name is this known?

    parent_files = task.fd_namespace
    await task.syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None) # type: ignore
    child_files = FDNamespace()
    task.fd_namespace = child_files
    context = SubprocessContext(task, child_files, parent_files)
    try:
        yield context
    finally:
        if context.pid is None:
            await context.exit(0)

class Process:
    """A single process addressed with a killfd and waitfd"""
    def __init__(self, killfd: AsyncFileDescriptor[WritableFile],
                 waitfd: AsyncFileDescriptor[ReadableFile],
                 pid: int) -> None:
        self.killfd = killfd
        self.waitfd = waitfd
        self.pid = pid
        self.child_event_buffer = supervise.ChildEventBuffer()

    async def close(self) -> None:
        await self.killfd.aclose()
        await self.waitfd.aclose()

    async def events(self) -> t.Any:
        while True:
            ret = await self.waitfd.read()
            if len(ret) == 0:
                # EOF
                return
            self.child_event_buffer.feed(ret)
            while True:
                event = self.child_event_buffer.consume()
                if event:
                    yield event
                else:
                    break

    async def check(self) -> None:
        async for event in self.events():
            if event.pid != self.pid:
                continue
            if event.died():
                return event.check()
        raise supervise.UncleanExit()

    async def send_signal(self, signum: signal.Signals):
        """Send this signal to the main child process."""
        if not isinstance(signum, int):
            raise TypeError("signum must be an integer: {}".format(signum))
        msg = supervise.ffi.new('struct supervise_send_signal*', {'pid':self.pid, 'signal':signum})
        buf = bytes(ffi.buffer(msg))
        await self.killfd.write(buf)

    async def terminate(self):
        """Terminate the main child process with SIGTERM.

        Note that this does not kill all descendent processes.
        For that, call close().
        """
        await self.send_signal(signal.SIGTERM)

    async def kill(self):
        """Kill the main child process with SIGKILL.

        Note that this does not kill all descendent processes.
        For that, call close().
        """
        await self.send_signal(signal.SIGKILL)

class RawProcess:
    def __init__(self, killfd: FileDescriptor[WritableFile],
                 waitfd: FileDescriptor[ReadableFile],
                 pid: int) -> None:
        self.killfd = killfd
        self.waitfd = waitfd
        self.pid = pid

    async def make_async(self, epoller: Epoller) -> Process:
        async_killfd = await AsyncFileDescriptor.make(epoller, self.killfd)
        async_waitfd = await AsyncFileDescriptor.make(epoller, self.waitfd)
        return Process(async_killfd, async_waitfd, self.pid)

class SupervisedSubprocessContext:
    def __init__(self, super_subproc: SubprocessContext, user_subproc: SubprocessContext) -> None:
        self.super_subproc = super_subproc
        self.user_subproc = user_subproc
        self.raw_proc: t.Optional[RawProcess] = None

    def translate(self, fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
        return self.super_subproc.translate(self.user_subproc.translate(fd))

    async def exit(self, status: int) -> None:
        await self.user_subproc.exit(status)

    async def exec(self, path: Path, argv: t.List[t.Union[str, bytes]],
                   *, envp: t.Optional[t.Dict[str, str]]=None) -> None:
        await self.user_subproc.exec(path, argv, envp=envp)

@asynccontextmanager
async def clonefd(task: Task, stdstreams: StandardStreams) -> t.Any:
    async with (await allocate_pipe(task)) as pipe_in:
        async with (await allocate_pipe(task)) as pipe_out:
            async with subprocess(task) as super_proc:
                os.setsid()
                prctl.set_child_subreaper(True)
                try:
                    async with subprocess(task) as user_proc:
                        supervised_subproc = SupervisedSubprocessContext(super_proc, user_proc)
                        yield supervised_subproc
                finally:
                    # we launch supervise regardless of whether an exception is thrown,
                    # to clean up child processes.
                    await super_proc.translate(pipe_in.rfd).dup2(
                        super_proc.translate(stdstreams.stdin))
                    await super_proc.translate(pipe_out.wfd).dup2(
                        super_proc.translate(stdstreams.stdout))
                    await super_proc.exec(supervise.supervise_utility_location, [], envp={})
            supervised_subproc.raw_proc = RawProcess(
                pipe_in.wfd.release(), pipe_out.rfd.release(), user_proc.pid)
