from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import struct
import os
import enum
import abc
import logging
import typing as t
logger = logging.getLogger(__name__)

from rsyscall.fcntl import AT, F
from rsyscall.sys.wait import IdType
if t.TYPE_CHECKING:
    from rsyscall.sys.epoll import EPOLL_CTL
    from rsyscall.sys.prctl import PR
    from rsyscall.sys.socket import SHUT
    from rsyscall.sys.uio import RWF
    from rsyscall.sched import CLONE
    from rsyscall.signal import HowSIG, Signals
    import rsyscall.handle as handle

class SYS(enum.IntEnum):
    read = lib.SYS_read
    write = lib.SYS_write
    pread64 = lib.SYS_pread64
    recvfrom = lib.SYS_recvfrom
    close = lib.SYS_close
    fcntl = lib.SYS_fcntl
    sendmsg = lib.SYS_sendmsg
    recvmsg = lib.SYS_recvmsg
    dup3 = lib.SYS_dup3
    accept4 = lib.SYS_accept4
    shutdown = lib.SYS_shutdown
    memfd_create = lib.SYS_memfd_create
    ftruncate = lib.SYS_ftruncate
    mmap = lib.SYS_mmap
    munmap = lib.SYS_munmap
    set_tid_address = lib.SYS_set_tid_address
    set_robust_list = lib.SYS_set_robust_list
    getdents64 = lib.SYS_getdents64
    unshare = lib.SYS_unshare
    epoll_ctl = lib.SYS_epoll_ctl
    epoll_wait = lib.SYS_epoll_wait
    chdir = lib.SYS_chdir
    fchdir = lib.SYS_fchdir
    getuid = lib.SYS_getuid
    getgid = lib.SYS_getgid
    mount = lib.SYS_mount
    waitid = lib.SYS_waitid
    setns = lib.SYS_setns
    prctl = lib.SYS_prctl
    setsid = lib.SYS_setsid
    inotify_init1 = lib.SYS_inotify_init1
    inotify_add_watch = lib.SYS_inotify_add_watch
    inotify_rm_watch = lib.SYS_inotify_rm_watch
    ioctl = lib.SYS_ioctl
    socket = lib.SYS_socket
    bind = lib.SYS_bind
    capget = lib.SYS_capget
    capset = lib.SYS_capset
    listen = lib.SYS_listen
    getsockopt = lib.SYS_getsockopt
    setsockopt = lib.SYS_setsockopt
    rt_sigaction = lib.SYS_rt_sigaction
    rt_sigprocmask = lib.SYS_rt_sigprocmask
    openat = lib.SYS_openat
    mkdirat = lib.SYS_mkdirat
    faccessat = lib.SYS_faccessat
    unlinkat = lib.SYS_unlinkat
    linkat = lib.SYS_linkat
    renameat2 = lib.SYS_renameat2
    symlinkat = lib.SYS_symlinkat
    readlinkat = lib.SYS_readlinkat
    lseek = lib.SYS_lseek
    signalfd4 = lib.SYS_signalfd4
    epoll_create1 = lib.SYS_epoll_create1
    connect = lib.SYS_connect
    getpeername = lib.SYS_getpeername
    getsockname = lib.SYS_getsockname
    pipe2 = lib.SYS_pipe2
    socketpair = lib.SYS_socketpair
    execveat = lib.SYS_execveat
    kill = lib.SYS_kill
    exit = lib.SYS_exit
    clone = lib.SYS_clone
    preadv2 = lib.SYS_preadv2
    pwritev2 = lib.SYS_pwritev2
    fchmod = lib.SYS_fchmod

# This is like the segment register override prefix, with no awareness of the contents of the register.
class SyscallResponse:
    # Throws on negative return value
    @abc.abstractmethod
    async def receive(self) -> int:
        pass

class SyscallInterface:
    # Throws on negative return value
    @abc.abstractmethod
    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int: ...
    # Only implemented for remote syscall interfaces.
    @abc.abstractmethod
    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse: ...
    # non-syscall operations which we haven't figured out how to get rid of yet
    @abc.abstractmethod
    async def close_interface(self) -> None: ...
    # when this file descriptor is readable, it means other things want to run on this thread.
    # Users of the SyscallInterface should ensure that when they block, they are monitoring this fd as well.
    # Typically, this is in fact the fd which the rsyscall server reads for incoming system calls!
    @abc.abstractmethod
    def get_activity_fd(self) -> t.Optional[handle.FileDescriptor]: ...
    # This is some process which is useful to identify this syscall interface.
    identifier_process: Process

# This is like a near pointer.
@dataclass(frozen=True)
class FileDescriptor:
    number: int

    def __str__(self) -> str:
        return f"FD({self.number})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.number

@dataclass(frozen=True)
class WatchDescriptor:
    number: int

    def __str__(self) -> str:
        return f"WD({self.number})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.number

@dataclass
class Pointer:
    address: int

    def __add__(self, other: int) -> 'Pointer':
        return Pointer(self.address + other)

    def __sub__(self, other: int) -> 'Pointer':
        return Pointer(self.address - other)

    def __str__(self) -> str:
        return f"Pointer({hex(self.address)})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.address

# This is like the actual memory. Not sure what to think of this.
@dataclass(eq=False)
class File:
    pass

class DirectoryFile(File):
    pass

@dataclass
class MemoryMapping:
    address: int
    length: int
    page_size: int

    def __post_init_(self) -> None:
        # the address and length are page-aligned
        assert (self.address % self.page_size) == 0
        assert (self.length % self.page_size) == 0

    def as_pointer(self) -> Pointer:
        return Pointer(self.address)

    def __str__(self) -> str:
        if self.page_size == 4096:
            return f"MMap({hex(self.address)}, {self.length})"
        else:
            return f"MMap(pgsz={self.page_size}, {hex(self.address)}, {self.length})"

    def __repr__(self) -> str:
        return str(self)

@dataclass
class Process:
    id: int

    def __int__(self) -> int:
        return self.id

@dataclass
class ProcessGroup:
    id: int

    def __int__(self) -> int:
        return self.id

# This is like an instruction, run with this segment register override prefix and arguments.
async def read(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    return (await sysif.syscall(SYS.read, fd, buf, count))

async def write(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    return (await sysif.syscall(SYS.write, fd, buf, count))

async def pread(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int, offset: int) -> int:
    return (await sysif.syscall(SYS.pread64, fd, buf, count, offset))

async def preadv2(sysif: SyscallInterface, fd: FileDescriptor, iov: Pointer, iovcnt: int, offset: int, flags: RWF) -> int:
    return (await sysif.syscall(SYS.preadv2, fd, iov, iovcnt, offset, flags))

async def pwritev2(sysif: SyscallInterface, fd: FileDescriptor, iov: Pointer, iovcnt: int, offset: int, flags: RWF) -> int:
    return (await sysif.syscall(SYS.pwritev2, fd, iov, iovcnt, offset, flags))

async def recv(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int, flags: int) -> int:
    return (await sysif.syscall(SYS.recvfrom, fd, buf, count, flags))

async def close(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    await sysif.syscall(SYS.close, fd)

async def fcntl(sysif: SyscallInterface, fd: FileDescriptor, cmd: F, arg: t.Optional[t.Union[int, Pointer]]=None) -> int:
    logger.debug("fcntl(%s, %s, %s)", fd, cmd, arg)
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.fcntl, fd, cmd, arg))

async def sendmsg(sysif: SyscallInterface, fd: FileDescriptor, msg: Pointer, flags: int) -> int:
    return (await sysif.syscall(SYS.sendmsg, fd, msg, flags))

async def recvmsg(sysif: SyscallInterface, fd: FileDescriptor, msg: Pointer, flags: int) -> int:
    return (await sysif.syscall(SYS.recvmsg, fd, msg, flags))

async def dup3(sysif: SyscallInterface, oldfd: FileDescriptor, newfd: FileDescriptor, flags: int) -> None:
    await sysif.syscall(SYS.dup3, oldfd, newfd, flags)

async def accept4(sysif: SyscallInterface, sockfd: FileDescriptor,
                  addr: t.Optional[Pointer], addrlen: t.Optional[Pointer], flags: int) -> FileDescriptor:
    if addr is None:
        addr = 0 # type: ignore
    if addrlen is None:
        addrlen = 0 # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.accept4, sockfd, addr, addrlen, flags))

async def shutdown(sysif: SyscallInterface, sockfd: FileDescriptor, how: SHUT) -> None:
    await sysif.syscall(SYS.shutdown, sockfd, how)

async def memfd_create(sysif: SyscallInterface, name: Pointer, flags: int) -> FileDescriptor:
    ret = await sysif.syscall(SYS.memfd_create, name, flags)
    return FileDescriptor(ret)

async def ftruncate(sysif: SyscallInterface, fd: FileDescriptor, length: int) -> None:
    await sysif.syscall(SYS.ftruncate, fd, length)

async def mmap(sysif: SyscallInterface, length: int, prot: int, flags: int,
               addr: t.Optional[Pointer]=None, 
               fd: t.Optional[FileDescriptor]=None, offset: int=0,
               page_size: int=4096) -> MemoryMapping:
    if addr is None:
        addr = 0 # type: ignore
    else:
        assert (int(addr) % page_size) == 0
    if fd is None:
        fd = -1 # type: ignore
    # TODO we want Linux to enforce this for us, but instead it just rounds,
    # leaving us unable to later munmap.
    assert (int(length) % page_size) == 0
    ret = await sysif.syscall(SYS.mmap, addr, length, prot, flags, fd, offset)
    return MemoryMapping(address=ret, length=length, page_size=page_size)

async def munmap(sysif: SyscallInterface, mapping: MemoryMapping) -> None:
    await sysif.syscall(SYS.munmap, mapping.address, mapping.length)

async def set_tid_address(sysif: SyscallInterface, ptr: Pointer) -> None:
    await sysif.syscall(SYS.set_tid_address, ptr)

async def set_robust_list(sysif: SyscallInterface, head: Pointer, len: int) -> None:
    await sysif.syscall(SYS.set_robust_list, head, len)

async def getdents64(sysif: SyscallInterface, fd: FileDescriptor, dirp: Pointer, count: int) -> int:
    return (await sysif.syscall(SYS.getdents64, fd, dirp, count))

async def unshare(sysif: SyscallInterface, flags: CLONE) -> None:
    await sysif.syscall(SYS.unshare, flags)

async def epoll_ctl(sysif: SyscallInterface, epfd: FileDescriptor, op: EPOLL_CTL,
                    fd: FileDescriptor, event: t.Optional[Pointer]=None) -> None:
    if event is None:
        event = 0 # type: ignore
    await sysif.syscall(SYS.epoll_ctl, epfd, op, fd, event)

async def epoll_wait(sysif: SyscallInterface, epfd: FileDescriptor, events: Pointer, maxevents: int, timeout: int) -> int:
    return (await sysif.syscall(SYS.epoll_wait, epfd, events, maxevents, timeout))

async def chdir(sysif: SyscallInterface, path: Pointer) -> None:
    await sysif.syscall(SYS.chdir, path)

async def fchdir(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    await sysif.syscall(SYS.fchdir, fd)

async def getuid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getuid))

async def getgid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getgid))

async def mount(sysif: SyscallInterface, source: Pointer, target: Pointer,
                filesystemtype: Pointer, mountflags: int,
                data: Pointer) -> None:
    await sysif.syscall(SYS.mount, source, target, filesystemtype, mountflags, data)

async def setns(sysif: SyscallInterface, fd: FileDescriptor, nstype: int) -> None:
    await sysif.syscall(SYS.setns, fd, nstype)

async def prctl(sysif: SyscallInterface, option: PR, arg2: int,
                arg3: t.Optional[int], arg4: t.Optional[int], arg5: t.Optional[int]) -> int:
    if arg3 is None:
        arg3 = 0
    if arg4 is None:
        arg4 = 0
    if arg5 is None:
        arg5 = 0
    return (await sysif.syscall(SYS.prctl, option, arg2, arg3, arg4, arg5))

async def setsid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.setsid))

async def inotify_init(sysif: SyscallInterface, flags: int) -> FileDescriptor:
    return FileDescriptor(await sysif.syscall(SYS.inotify_init1, flags))

async def inotify_add_watch(sysif: SyscallInterface, fd: FileDescriptor, pathname: Pointer, mask: int) -> WatchDescriptor:
    return WatchDescriptor(await sysif.syscall(SYS.inotify_add_watch, fd, pathname, mask))

async def inotify_rm_watch(sysif: SyscallInterface, fd: FileDescriptor, wd: WatchDescriptor) -> None:
    await sysif.syscall(SYS.inotify_rm_watch, fd, wd)

async def ioctl(sysif: SyscallInterface, fd: FileDescriptor, request: int,
                arg: t.Optional[t.Union[int, Pointer]]=None) -> int:
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.ioctl, fd, request, arg))

async def socket(sysif: SyscallInterface, domain: int, type: int, protocol: int) -> FileDescriptor:
    return FileDescriptor(await sysif.syscall(SYS.socket, domain, type, protocol))

async def bind(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: int) -> None:
    await sysif.syscall(SYS.bind, sockfd, addr, addrlen)

async def capset(sysif: SyscallInterface, hdrp: Pointer, datap: Pointer) -> None:
    await sysif.syscall(SYS.capset, hdrp, datap)

async def capget(sysif: SyscallInterface, hdrp: Pointer, datap: Pointer) -> None:
    await sysif.syscall(SYS.capget, hdrp, datap)

async def listen(sysif: SyscallInterface, sockfd: FileDescriptor, backlog: int) -> None:
    await sysif.syscall(SYS.listen, sockfd, backlog)

async def getsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int, optval: Pointer, optlen: Pointer) -> None:
    await sysif.syscall(SYS.getsockopt, sockfd, level, optname, optval, optlen)

async def setsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int,
                     optval: Pointer, optlen: int) -> None:
    await sysif.syscall(SYS.setsockopt, sockfd, level, optname, optval, optlen)

async def getsockname(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: Pointer) -> None:
    await sysif.syscall(SYS.getsockname, sockfd, addr, addrlen)

async def getpeername(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: Pointer) -> None:
    await sysif.syscall(SYS.getpeername, sockfd, addr, addrlen)

async def rt_sigaction(sysif: SyscallInterface, signum: Signals,
                       act: t.Optional[Pointer],
                       oldact: t.Optional[Pointer],
                       size: int) -> None:
    if act is None:
        act = 0 # type: ignore
    if oldact is None:
        oldact = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigaction, signum, act, oldact, size)

async def rt_sigprocmask(sysif: SyscallInterface,
                         newset: t.Optional[t.Tuple[HowSIG, Pointer]],
                         oldset: t.Optional[Pointer],
                         sigsetsize: int) -> None:
    if newset is not None:
        how, set = newset
    else:
        how, set = 0, 0 # type: ignore
    if oldset is None:
        oldset = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigprocmask, how, set, oldset, sigsetsize)

async def openat(sysif: SyscallInterface, dirfd: t.Optional[FileDescriptor],
                 path: Pointer, flags: int, mode: int) -> FileDescriptor:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.openat, dirfd, path, flags, mode))

async def fchmod(sysif: SyscallInterface, fd: FileDescriptor, mode: int) -> None:
    await sysif.syscall(SYS.fchmod, fd, mode)

async def mkdirat(sysif: SyscallInterface,
                  dirfd: t.Optional[FileDescriptor], path: Pointer, mode: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.mkdirat, dirfd, path, mode)

async def faccessat(sysif: SyscallInterface,
                    dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int, mode: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.faccessat, dirfd, path, flags, mode)

async def unlinkat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.unlinkat, dirfd, path, flags)

async def linkat(sysif: SyscallInterface,
                 olddirfd: t.Optional[FileDescriptor], oldpath: Pointer,
                 newdirfd: t.Optional[FileDescriptor], newpath: Pointer,
                 flags: int) -> None:
    if olddirfd is None:
        olddirfd = AT.FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.linkat, olddirfd, oldpath, newdirfd, newpath, flags)

async def renameat2(sysif: SyscallInterface,
                    olddirfd: t.Optional[FileDescriptor], oldpath: Pointer,
                    newdirfd: t.Optional[FileDescriptor], newpath: Pointer,
                    flags: int) -> None:
    if olddirfd is None:
        olddirfd = AT.FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.renameat2, olddirfd, oldpath, newdirfd, newpath, flags)

async def symlinkat(sysif: SyscallInterface,
                    target: Pointer, newdirfd: t.Optional[FileDescriptor], linkpath: Pointer) -> None:
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.symlinkat, target, newdirfd, linkpath)

async def readlinkat(sysif: SyscallInterface,
                     dirfd: t.Optional[FileDescriptor], path: Pointer,
                     buf: Pointer, bufsiz: int) -> int:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return (await sysif.syscall(SYS.readlinkat, dirfd, path, buf, bufsiz))

async def lseek(sysif: SyscallInterface, fd: FileDescriptor, offset: int, whence: int) -> int:
    return (await sysif.syscall(SYS.lseek, fd, offset, whence))

async def signalfd4(sysif: SyscallInterface, fd: t.Optional[FileDescriptor],
                    mask: Pointer, sizemask: int, flags: int) -> FileDescriptor:
    if fd is None:
        fd = -1 # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.signalfd4, fd, mask, sizemask, flags))

async def epoll_create(sysif: SyscallInterface, flags: int) -> FileDescriptor:
    return FileDescriptor(await sysif.syscall(SYS.epoll_create1, flags))

async def connect(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: int) -> None:
    await sysif.syscall(SYS.connect, sockfd, addr, addrlen)

async def waitid(sysif: SyscallInterface,
                 id: t.Union[Process, ProcessGroup, None], infop: t.Optional[Pointer], options: int,
                 rusage: t.Optional[Pointer]) -> int:
    logger.debug("waitid(%s, %s, %s, %s)", id, infop, options, rusage)
    if isinstance(id, Process):
        idtype = IdType.PID
    elif isinstance(id, ProcessGroup):
        idtype = IdType.PGID
    elif id is None:
        idtype = IdType.ALL
        id = 0 # type: ignore
    else:
        raise ValueError("unknown id type", id)
    if infop is None:
        infop = 0 # type: ignore
    if rusage is None:
        rusage = 0 # type: ignore
    return (await sysif.syscall(SYS.waitid, idtype, id, infop, options, rusage))

async def pipe2(sysif: SyscallInterface, pipefd: Pointer, flags: int) -> None:
    await sysif.syscall(SYS.pipe2, pipefd, flags)

async def socketpair(sysif: SyscallInterface, domain: int, type: int, protocol: int, sv: Pointer) -> None:
    await sysif.syscall(SYS.socketpair, domain, type, protocol, sv)

import trio
from rsyscall.tasks.exceptions import RsyscallHangup
async def execveat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Pointer,
                   argv: Pointer, envp: Pointer, flags: int) -> None:
    logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    def handle(exn):
        if isinstance(exn, RsyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execveat, dirfd, path, argv, envp, flags)

async def exit(sysif: SyscallInterface, status: int) -> None:
    def handle(exn):
        if isinstance(exn, RsyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.exit, status)

async def kill(sysif: SyscallInterface, pid: Process, sig: Signals) -> None:
    await sysif.syscall(SYS.kill, pid, sig)

async def clone(sysif: SyscallInterface, flags: int, child_stack: Pointer,
                ptid: t.Optional[Pointer], ctid: t.Optional[Pointer],
                newtls: t.Optional[Pointer]) -> Process:
    # I don't use CLONE_THREAD, so I can say without confusion, that clone returns a Process.
    if child_stack is None:
        child_stack = 0 # type: ignore
    if ptid is None:
        ptid = 0 # type: ignore
    if ctid is None:
        ctid = 0 # type: ignore
    if newtls is None:
        newtls = 0 # type: ignore
    return Process(await sysif.syscall(SYS.clone, flags, child_stack, ptid, ctid, newtls))

