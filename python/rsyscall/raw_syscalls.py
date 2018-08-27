from rsyscall.base import SyscallInterface, Task, FileDescriptor, Pointer, RsyscallException, RsyscallHangup
from rsyscall._raw import ffi, lib # type: ignore
import logging
logger = logging.getLogger(__name__)

# TODO verify that pointers and file descriptors come from the same
# address space and fd namespace as the task.
async def pipe(task: Task, buf: Pointer, flags: int) -> None:
    logger.debug("pipe(%s, %s)", buf, flags)
    await task.sysif.syscall(lib.SYS_pipe2, buf, flags)

async def close(task: Task, fd: FileDescriptor) -> None:
    logger.debug("close(%s)", fd)
    await task.sysif.syscall(lib.SYS_close, fd)

async def read(task: Task, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("read(%s, %s, %d)", fd, buf, count)
    return (await task.sysif.syscall(lib.SYS_read, fd, buf, count))

async def write(task: Task, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("write(%s, %s, %d)", fd, buf, count)
    return (await task.sysif.syscall(lib.SYS_write, fd, buf, count))

async def dup2(task: Task, oldfd: FileDescriptor, newfd: FileDescriptor) -> None:
    logger.debug("dup2(%s, %s)", oldfd, newfd)
    await task.sysif.syscall(lib.SYS_dup2, oldfd, newfd)

async def clone(task: Task, flags: int, child_stack: Pointer,
                ptid: Pointer, ctid: Pointer,
                newtls: Pointer) -> int:
    logger.debug("clone(%s, %s, %s, %s, %s)", flags, child_stack, ptid, ctid, newtls)
    return (await task.sysif.syscall(lib.SYS_clone, flags, child_stack, ptid, ctid, newtls))

async def exit(task: Task, status: int) -> None:
    logger.debug("exit(%d)", status)
    try:
        await task.sysif.syscall(lib.SYS_exit, status)
    except RsyscallHangup:
        # a hangup means the exit was successful
        pass

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

async def epoll_ctl(sysif: SyscallInterface, epfd: FileDescriptor, op: int, fd: FileDescriptor, event: Pointer=None) -> None:
    if event is None:
        logger.debug("epoll_ctl(%d, %s, %d)", epfd, op, fd)
        await sysif.syscall(lib.SYS_epoll_ctl, epfd, op, fd, 0)
    else:
        logger.debug("epoll_ctl(%d, %s, %d, %s)", epfd, op, fd, event)
        await sysif.syscall(lib.SYS_epoll_ctl, epfd, op, fd, event)

async def epoll_wait(sysif: SyscallInterface, epfd: FileDescriptor, events: Pointer, maxevents: int, timeout: int) -> int:
    logger.debug("epoll_wait(%d, %d, %d, %d)", epfd, events, maxevents, timeout)
    return (await sysif.syscall(lib.SYS_epoll_wait, epfd, events, maxevents, timeout))
