from rsyscall.base import SyscallInterface, Task, FileDescriptor, Pointer, Process, ProcessGroup, RsyscallException, RsyscallHangup
from rsyscall._raw import ffi, lib # type: ignore
import logging
import signal
import typing as t
import enum
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class NsType(enum.IntFlag):
    NEWCGROUP = lib.CLONE_NEWCGROUP
    NEWIPC = lib.CLONE_NEWIPC
    NEWNET = lib.CLONE_NEWNET
    NEWNS = lib.CLONE_NEWNS
    NEWPID = lib.CLONE_NEWPID
    NEWUSER = lib.CLONE_NEWUSER
    NEWUTS = lib.CLONE_NEWUTS

class UnshareFlag(enum.IntFlag):
    NONE = 0
    FILES = lib.CLONE_FILES
    FS = lib.CLONE_FS
    NEWCGROUP = lib.CLONE_NEWCGROUP
    NEWIPC = lib.CLONE_NEWIPC
    NEWNET = lib.CLONE_NEWNET
    NEWNS = lib.CLONE_NEWNS
    NEWPID = lib.CLONE_NEWPID
    NEWUSER = lib.CLONE_NEWUSER
    NEWUTS = lib.CLONE_NEWUTS
    SYSVSEM = lib.CLONE_SYSVSEM

class SigprocmaskHow(enum.IntEnum):
    BLOCK = lib.SIG_BLOCK
    UNBLOCK = lib.SIG_UNBLOCK
    SETMASK = lib.SIG_SETMASK

class IdType(enum.IntEnum):
    PID = lib.P_PID # Wait for the child whose process ID matches id.
    PGID = lib.P_PGID # Wait for any child whose process group ID matches id.
    ALL = lib.P_ALL # Wait for any child; id is ignored.

class SYS(enum.IntEnum):
    accept4 = lib.SYS_accept4
    bind = lib.SYS_bind
    chdir = lib.SYS_chdir
    clone = lib.SYS_clone
    close = lib.SYS_close
    connect = lib.SYS_connect
    dup3 = lib.SYS_dup3
    epoll_create1 = lib.SYS_epoll_create1
    epoll_ctl = lib.SYS_epoll_ctl
    epoll_wait = lib.SYS_epoll_wait
    execveat = lib.SYS_execveat
    exit = lib.SYS_exit
    faccessat = lib.SYS_faccessat
    fchdir = lib.SYS_fchdir
    fcntl = lib.SYS_fcntl
    getdents64 = lib.SYS_getdents64
    getpeername = lib.SYS_getpeername
    getpid = lib.SYS_getpid
    getsockname = lib.SYS_getsockname
    getsockopt = lib.SYS_getsockopt
    kill = lib.SYS_kill
    linkat = lib.SYS_linkat
    renameat2 = lib.SYS_renameat2
    listen = lib.SYS_listen
    lseek = lib.SYS_lseek
    mkdirat = lib.SYS_mkdirat
    mmap = lib.SYS_mmap
    munmap = lib.SYS_munmap
    openat = lib.SYS_openat
    pipe2 = lib.SYS_pipe2
    read = lib.SYS_read
    readlinkat = lib.SYS_readlinkat
    rt_sigprocmask = lib.SYS_rt_sigprocmask
    setsockopt = lib.SYS_setsockopt
    signalfd4 = lib.SYS_signalfd4
    socket = lib.SYS_socket
    socketpair = lib.SYS_socketpair
    symlinkat = lib.SYS_symlinkat
    unlinkat = lib.SYS_unlinkat
    unshare = lib.SYS_unshare
    waitid = lib.SYS_waitid
    write = lib.SYS_write

# TODO verify that pointers and file descriptors come from the same
# address space and fd namespace as the task.

#### Syscalls which can be used without memory access. ####
async def close(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    logger.debug("close(%s)", fd)
    await sysif.syscall(SYS.close, fd)

async def dup3(sysif: SyscallInterface, oldfd: FileDescriptor, newfd: FileDescriptor, flags: int) -> None:
    logger.debug("dup3(%s, %s, %d)", oldfd, newfd, flags)
    await sysif.syscall(SYS.dup3, oldfd, newfd, flags)

async def mmap(sysif: SyscallInterface, length: int, prot: int, flags: int,
               addr: t.Optional[Pointer]=None, 
               fd: t.Optional[FileDescriptor]=None, offset: int=0) -> int:
    logger.debug("mmap(%s, %s, %s, %s, %s, %s)", addr, length, prot, flags, fd, offset)
    if addr is None:
        addr = 0 # type: ignore
    if fd is None:
        fd = -1 # type: ignore
    return (await sysif.syscall(SYS.mmap, addr, length, prot, flags, -1, offset))

async def munmap(sysif: SyscallInterface, addr: Pointer, length: int) -> None:
    logger.debug("munmap(%s, %s)", addr, length)
    await sysif.syscall(SYS.munmap, addr, length)

async def getpid(sysif: SyscallInterface) -> int:
    logger.debug("getpid()")
    return (await sysif.syscall(SYS.getpid))

async def exit(sysif: SyscallInterface, status: int) -> None:
    logger.debug("exit(%d)", status)
    try:
        await sysif.syscall(SYS.exit, status)
    except RsyscallHangup:
        # a hangup means the exit was successful
        pass

async def kill(sysif: SyscallInterface, pid: Process, sig: signal.Signals) -> None:
    logger.debug("kill(%s, %s)", pid, sig)
    await sysif.syscall(SYS.kill, pid, sig)

async def unshare(sysif: SyscallInterface, flags: UnshareFlag) -> None:
    logger.debug("unshare(%s)", flags)
    await sysif.syscall(SYS.unshare, flags)
    
async def setns(sysif: SyscallInterface, fd: int, nstype: NsType) -> None:
    raise NotImplementedError

async def socket(sysif: SyscallInterface, domain: int, type: int, protocol: int) -> int:
    logger.debug("socket(%s, %s, %s)", domain, type, protocol)
    return (await sysif.syscall(SYS.socket, domain, type, protocol))

async def fcntl(sysif: SyscallInterface, fd: FileDescriptor, cmd: int, arg: t.Optional[t.Union[int, Pointer]]=None) -> int:
    logger.debug("fcntl(%s, %s, %s)", fd, cmd, arg)
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.fcntl, fd, cmd, arg))

async def fchdir(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    logger.debug("fchdir(%s)", fd)
    await sysif.syscall(SYS.fchdir, fd)

async def lseek(sysif: SyscallInterface, fd: FileDescriptor, offset: int, whence: int) -> int:
    logger.debug("lseek(%s, %s, %s)", fd, offset, whence)
    return (await sysif.syscall(SYS.lseek, fd, offset, whence))

async def listen(sysif: SyscallInterface, sockfd: FileDescriptor, backlog: int) -> None:
    logger.debug("listen(%s, %s)", sockfd, backlog)
    await sysif.syscall(SYS.listen, sockfd, backlog)

async def waitid(sysif: SyscallInterface,
                 id: t.Union[Process, ProcessGroup, None], infop: t.Optional[Pointer], options: int, rusage: t.Optional[Pointer]) -> int:
    logger.debug("waitid(%s, %s, %s, %s)", id, infop, options, rusage)
    if isinstance(id, Process):
        idtype, idnum = IdType.PID, id.id
    elif isinstance(id, ProcessGroup):
        idtype, idnum = IdType.PGID, id.id
    elif id is None:
        idtype, idnum = IdType.ALL, 0
    else:
        raise ValueError("unknown id type", id)
    if infop is None:
        infop = 0 # type: ignore
    if rusage is None:
        rusage = 0 # type: ignore
    return (await sysif.syscall(SYS.waitid, idtype, idnum, infop, options, rusage))

#### Syscalls which need read or write memory access and allocation to be used. ####
async def pipe2(sysif: SyscallInterface, pipefd: Pointer, flags: int) -> None:
    logger.debug("pipe2(%s, %s)", pipefd, flags)
    await sysif.syscall(SYS.pipe2, pipefd, flags)

async def read(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("read(%s, %s, %d)", fd, buf, count)
    return (await sysif.syscall(SYS.read, fd, buf, count))

async def write(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("write(%s, %s, %d)", fd, buf, count)
    return (await sysif.syscall(SYS.write, fd, buf, count))

async def clone(sysif: SyscallInterface, flags: int, child_stack: t.Optional[Pointer],
                ptid: t.Optional[Pointer], ctid: t.Optional[Pointer],
                newtls: t.Optional[Pointer]) -> int:
    logger.debug("clone(%s, %s, %s, %s, %s)", flags, child_stack, ptid, ctid, newtls)
    if child_stack is None:
        child_stack = 0 # type: ignore
    if ptid is None:
        ptid = 0 # type: ignore
    if ctid is None:
        ctid = 0 # type: ignore
    if newtls is None:
        newtls = 0 # type: ignore
    return (await sysif.syscall(SYS.clone, flags, child_stack, ptid, ctid, newtls))

async def epoll_create(sysif: SyscallInterface, flags: int) -> int:
    logger.debug("epoll_create(%s)", flags)
    return (await sysif.syscall(SYS.epoll_create1, flags))

async def epoll_ctl(sysif: SyscallInterface, epfd: FileDescriptor, op: int, fd: FileDescriptor, event: t.Optional[Pointer]=None) -> None:
    if event is None:
        logger.debug("epoll_ctl(%d, %s, %d)", epfd, op, fd)
        await sysif.syscall(SYS.epoll_ctl, epfd, op, fd, 0)
    else:
        logger.debug("epoll_ctl(%d, %s, %d, %s)", epfd, op, fd, event)
        await sysif.syscall(SYS.epoll_ctl, epfd, op, fd, event)

async def epoll_wait(sysif: SyscallInterface, epfd: FileDescriptor, events: Pointer, maxevents: int, timeout: int) -> int:
    logger.debug("epoll_wait(%d, %d, %d, %d)", epfd, events, maxevents, timeout)
    return (await sysif.syscall(SYS.epoll_wait, epfd, events, maxevents, timeout))

async def signalfd4(sysif: SyscallInterface, mask: Pointer, sizemask: int, flags: int,
                   fd: t.Optional[FileDescriptor]=None) -> int:
    logger.debug("signalfd(%s, %s, %s, %s)", fd, mask, sizemask, flags)
    if fd is None:
        fd = -1 # type: ignore
    return (await sysif.syscall(SYS.signalfd4, fd, mask, sizemask, flags))

async def rt_sigprocmask(sysif: SyscallInterface,
                         newset: t.Optional[t.Tuple[SigprocmaskHow, Pointer]],
                         oldset: t.Optional[Pointer],
                         sigsetsize: int) -> None:
    logger.debug("rt_sigprocmask(%s, %s, %s)", newset, oldset, sigsetsize)
    if newset is not None:
        how, set = newset
    else:
        how, set = 0, 0 # type: ignore
    if oldset is None:
        oldset = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigprocmask, how, set, oldset, sigsetsize)

# filesystem stuff
async def chdir(sysif: SyscallInterface, path: Pointer) -> None:
    logger.debug("chdir(%s)", path)
    await sysif.syscall(SYS.chdir, path)

async def getdents(sysif: SyscallInterface, fd: FileDescriptor, dirp: Pointer, count: int) -> int:
    logger.debug("getdents64(%s, %s, %s)", fd, dirp, count)
    return (await sysif.syscall(SYS.getdents64, fd, dirp, count))

# operations on paths
async def openat(sysif: SyscallInterface,
                 dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int, mode: int) -> int:
    logger.debug("openat(%s, %s, %s, %s)", dirfd, path, flags, mode)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    return (await sysif.syscall(SYS.openat, dirfd, path, flags, mode))

async def faccessat(sysif: SyscallInterface,
                    dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int, mode: int) -> None:
    logger.debug("faccessat(%s, %s, %s, %s)", dirfd, path, flags, mode)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    await sysif.syscall(SYS.faccessat, dirfd, path, flags, mode)

async def mkdirat(sysif: SyscallInterface,
                  dirfd: t.Optional[FileDescriptor], path: Pointer, mode: int) -> None:
    logger.debug("mkdirat(%s, %s, %s)", dirfd, path, mode)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    await sysif.syscall(SYS.mkdirat, dirfd, path, mode)

async def unlinkat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int) -> None:
    logger.debug("unlinkat(%s, %s, %s)", dirfd, path, flags)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    await sysif.syscall(SYS.unlinkat, dirfd, path, flags)

async def linkat(sysif: SyscallInterface,
                 olddirfd: t.Optional[FileDescriptor], oldpath: Pointer,
                 newdirfd: t.Optional[FileDescriptor], newpath: Pointer,
                 flags: int) -> None:
    logger.debug("linkat(%s, %s, %s, %s, %s)", olddirfd, oldpath, newdirfd, newpath, flags)
    if olddirfd is None:
        olddirfd = lib.AT_FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = lib.AT_FDCWD # type: ignore
    await sysif.syscall(SYS.linkat, olddirfd, oldpath, newdirfd, newpath, flags)

async def renameat2(sysif: SyscallInterface,
                    olddirfd: t.Optional[FileDescriptor], oldpath: Pointer,
                    newdirfd: t.Optional[FileDescriptor], newpath: Pointer,
                    flags: int) -> None:
    logger.debug("renameat2(%s, %s, %s, %s, %s)", olddirfd, oldpath, newdirfd, newpath, flags)
    if olddirfd is None:
        olddirfd = lib.AT_FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = lib.AT_FDCWD # type: ignore
    await sysif.syscall(SYS.renameat2, olddirfd, oldpath, newdirfd, newpath, flags)

async def symlinkat(sysif: SyscallInterface,
                    newdirfd: t.Optional[FileDescriptor], linkpath: Pointer, target: Pointer) -> None:
    logger.debug("symlinkat(%s, %s, %s)", newdirfd, linkpath, target)
    if newdirfd is None:
        newdirfd = lib.AT_FDCWD # type: ignore
    # symlinkat is in the opposite order of usual, for no reason
    await sysif.syscall(SYS.symlinkat, target, newdirfd, linkpath)

async def readlinkat(sysif: SyscallInterface,
                     dirfd: t.Optional[FileDescriptor], path: Pointer,
                     buf: Pointer, bufsiz: int) -> int:
    logger.debug("readlinkat(%s, %s, %s, %s)", dirfd, path, buf, bufsiz)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    return (await sysif.syscall(SYS.readlinkat, dirfd, path, buf, bufsiz))

async def execveat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Pointer,
                   argv: Pointer, envp: Pointer, flags: int) -> None:
    logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    try:
        await sysif.syscall(SYS.execveat, dirfd, path, argv, envp, flags)
    except RsyscallHangup:
        # a hangup means the exec was successful. other exceptions will propagate through
        pass

# socket stuff
async def socketpair(sysif: SyscallInterface, domain: int, type: int, protocol: int, sv: Pointer) -> None:
    logger.debug("socketpair(%s, %s, %s, %s)", domain, type, protocol, sv)
    await sysif.syscall(SYS.socketpair, domain, type, protocol, sv)

async def getsockname(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: Pointer) -> None:
    logger.debug("getsockname(%s, %s, %s)", sockfd, addr, addrlen)
    await sysif.syscall(SYS.getsockname, sockfd, addr, addrlen)

async def getpeername(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: Pointer) -> None:
    logger.debug("getpeername(%s, %s, %s)", sockfd, addr, addrlen)
    await sysif.syscall(SYS.getpeername, sockfd, addr, addrlen)

async def getsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int, optval: Pointer, optlen: Pointer) -> None:
    logger.debug("getsockopt(%s, %s, %s, %s, %s)", sockfd, level, optname, optval, optlen)
    await sysif.syscall(SYS.getsockopt, sockfd, level, optname, optval, optlen)

async def setsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int, optval: Pointer, optlen: int) -> None:
    logger.debug("setsockopt(%s, %s, %s, %s, %s)", sockfd, level, optname, optval, optlen)
    await sysif.syscall(SYS.setsockopt, sockfd, level, optname, optval, optlen)

async def bind(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: int) -> None:
    logger.debug("bind(%s, %s, %s)", sockfd, addr, addrlen)
    await sysif.syscall(SYS.bind, sockfd, addr, addrlen)

async def connect(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: int) -> None:
    logger.debug("connect(%s, %s, %s)", sockfd, addr, addrlen)
    await sysif.syscall(SYS.connect, sockfd, addr, addrlen)

async def accept(sysif: SyscallInterface, sockfd: FileDescriptor,
                 addr: Pointer, addrlen: Pointer, flags: int) -> int:
    logger.debug("accept(%s, %s, %s, %s)", sockfd, addr, addrlen, flags)
    return (await sysif.syscall(SYS.accept4, sockfd, addr, addrlen, flags))
