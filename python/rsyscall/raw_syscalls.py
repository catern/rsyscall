from rsyscall.base import SyscallInterface, Task, FileDescriptor, Pointer, RsyscallException, RsyscallHangup
from rsyscall._raw import ffi, lib # type: ignore
import logging
import signal
import typing as t
import enum
logger = logging.getLogger(__name__)

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

# TODO verify that pointers and file descriptors come from the same
# address space and fd namespace as the task.

#### Syscalls which can be used without memory access. ####
async def close(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    logger.debug("close(%s)", fd)
    await sysif.syscall(lib.SYS_close, fd)

async def dup2(sysif: SyscallInterface, oldfd: FileDescriptor, newfd: FileDescriptor) -> None:
    logger.debug("dup2(%s, %s)", oldfd, newfd)
    await sysif.syscall(lib.SYS_dup2, oldfd, newfd)

async def mmap(sysif: SyscallInterface, length: int, prot: int, flags: int,
               addr: t.Optional[Pointer]=None, 
               fd: t.Optional[FileDescriptor]=None, offset: int=0) -> int:
    logger.debug("mmap(%s, %s, %s, %s, %s, %s)", addr, length, prot, flags, fd, offset)
    if addr is None:
        addr = 0 # type: ignore
    if fd is None:
        fd = -1 # type: ignore
    return (await sysif.syscall(lib.SYS_mmap, addr, length, prot, flags, -1, offset))

async def munmap(sysif: SyscallInterface, addr: Pointer, length: int) -> None:
    logger.debug("munmap(%s, %s)", addr, length)
    await sysif.syscall(lib.SYS_munmap, addr, length)

async def getpid(sysif: SyscallInterface) -> int:
    logger.debug("getpid()")
    return (await sysif.syscall(lib.SYS_getpid))

async def exit(sysif: SyscallInterface, status: int) -> None:
    logger.debug("exit(%d)", status)
    try:
        await sysif.syscall(lib.SYS_exit, status)
    except RsyscallHangup:
        # a hangup means the exit was successful
        pass

async def kill(sysif: SyscallInterface, pid: int, sig: signal.Signals) -> None:
    # TODO should probable wrap pid in something ProcessNamespace-relative
    logger.debug("kill(%s, %s)", pid, sig)
    await sysif.syscall(lib.SYS_kill, pid, sig)

async def unshare(sysif: SyscallInterface, flags: UnshareFlag) -> None:
    logger.debug("unshare(%s)", flags)
    await sysif.syscall(lib.SYS_unshare, flags)
    
async def setns(sysif: SyscallInterface, fd: int, nstype: NsType) -> None:
    raise NotImplementedError

async def socket(sysif: SyscallInterface, domain: int, type: int, protocol: int) -> int:
    logger.debug("socket(%s, %s, %s)", domain, type, protocol)
    return (await sysif.syscall(lib.SYS_socket, domain, type, protocol))

async def fcntl(sysif: SyscallInterface, fd: FileDescriptor, cmd: int, arg: t.Optional[t.Union[int, Pointer]]=None) -> int:
    logger.debug("fcntl(%s, %s, %s)", fd, cmd, arg)
    if arg is None:
        arg = 0
    return (await sysif.syscall(lib.SYS_fcntl, fd, cmd, arg))

async def fchdir(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    logger.debug("fchdir(%s)", fd)
    await sysif.syscall(lib.SYS_fchdir, fd)

async def lseek(sysif: SyscallInterface, fd: FileDescriptor, offset: int, whence: int) -> int:
    logger.debug("lseek(%s, %s, %s)", fd, offset, whence)
    return (await sysif.syscall(lib.SYS_lseek, fd, offset, whence))

#### Syscalls which need read or write memory access and allocation to be used. ####
async def pipe2(sysif: SyscallInterface, pipefd: Pointer, flags: int) -> None:
    logger.debug("pipe2(%s, %s)", pipefd, flags)
    await sysif.syscall(lib.SYS_pipe2, pipefd, flags)

async def read(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("read(%s, %s, %d)", fd, buf, count)
    return (await sysif.syscall(lib.SYS_read, fd, buf, count))

async def write(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("write(%s, %s, %d)", fd, buf, count)
    return (await sysif.syscall(lib.SYS_write, fd, buf, count))

async def clone(sysif: SyscallInterface, flags: int, child_stack: Pointer,
                ptid: Pointer, ctid: Pointer,
                newtls: Pointer) -> int:
    logger.debug("clone(%s, %s, %s, %s, %s)", flags, child_stack, ptid, ctid, newtls)
    return (await sysif.syscall(lib.SYS_clone, flags, child_stack, ptid, ctid, newtls))

async def execveat(sysif: SyscallInterface, dirfd: FileDescriptor, path: Pointer,
                   argv: Pointer, envp: Pointer, flags: int) -> None:
    logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
    try:
        await sysif.syscall(lib.SYS_execveat, dirfd, path, argv, envp, flags)
    except RsyscallHangup:
        # a hangup means the exec was successful. other exceptions will propagate through
        pass

async def epoll_create(sysif: SyscallInterface, flags: int) -> int:
    logger.debug("epoll_create(%s)", flags)
    return (await sysif.syscall(lib.SYS_epoll_create1, flags))

async def epoll_ctl(sysif: SyscallInterface, epfd: FileDescriptor, op: int, fd: FileDescriptor, event: t.Optional[Pointer]=None) -> None:
    if event is None:
        logger.debug("epoll_ctl(%d, %s, %d)", epfd, op, fd)
        await sysif.syscall(lib.SYS_epoll_ctl, epfd, op, fd, 0)
    else:
        logger.debug("epoll_ctl(%d, %s, %d, %s)", epfd, op, fd, event)
        await sysif.syscall(lib.SYS_epoll_ctl, epfd, op, fd, event)

async def epoll_wait(sysif: SyscallInterface, epfd: FileDescriptor, events: Pointer, maxevents: int, timeout: int) -> int:
    logger.debug("epoll_wait(%d, %d, %d, %d)", epfd, events, maxevents, timeout)
    return (await sysif.syscall(lib.SYS_epoll_wait, epfd, events, maxevents, timeout))

# filesystem stuff
async def openat(sysif: SyscallInterface,
                 dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int, mode: int) -> int:
    logger.debug("openat(%s, %s, %s, %s)", dirfd, path, flags, mode)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    return (await sysif.syscall(lib.SYS_openat, dirfd, path, flags, mode))

async def faccessat(sysif: SyscallInterface,
                    dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int, mode: int) -> int:
    logger.debug("faccessat(%s, %s, %s, %s)", dirfd, path, flags, mode)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    return (await sysif.syscall(lib.SYS_faccessat, dirfd, path, flags, mode))

async def mkdirat(sysif: SyscallInterface,
                  dirfd: t.Optional[FileDescriptor], path: Pointer, mode: int) -> int:
    logger.debug("mkdirat(%s, %s, %s)", dirfd, path, mode)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    return (await sysif.syscall(lib.SYS_mkdirat, dirfd, path, mode))

async def unlinkat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Pointer, flags: int) -> int:
    logger.debug("unlinkat(%s, %s, %s)", dirfd, path, flags)
    if dirfd is None:
        dirfd = lib.AT_FDCWD # type: ignore
    return (await sysif.syscall(lib.SYS_unlinkat, dirfd, path, flags))

# socket stuff
async def getsockname(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: Pointer) -> None:
    logger.debug("getsockname(%s, %s, %s)", sockfd, addr, addrlen)
    await sysif.syscall(lib.SYS_getsockname, sockfd, addr, addrlen)

async def getpeername(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Pointer, addrlen: Pointer) -> None:
    logger.debug("getpeername(%s, %s, %s)", sockfd, addr, addrlen)
    await sysif.syscall(lib.SYS_getpeername, sockfd, addr, addrlen)

async def getsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int, optval: Pointer, optlen: Pointer) -> None:
    logger.debug("getsockopt(%s, %s, %s, %s, %s)", sockfd, level, optname, optval, optlen)
    await sysif.syscall(lib.SYS_getsockopt, sockfd, level, optname, optval, optlen)

async def setsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int, optval: Pointer, optlen: int) -> None:
    logger.debug("setsockopt(%s, %s, %s, %s, %s)", sockfd, level, optname, optval, optlen)
    await sysif.syscall(lib.SYS_setsockopt, sockfd, level, optname, optval, optlen)
