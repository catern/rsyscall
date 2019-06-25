"""Definitions of namespace-local identifiers, syscalls, and SyscallInterface

These namespace-local identifiers are like near pointers, in systems
with segmented memory. They are valid only within a specific segment
(namespace).

The syscalls are instructions, operating on near pointers and other
arguments.

The SyscallInterface is the segment register override prefix, which is
used with the instruction to say which segment register to use for the
syscall.

We don't know from a segment register override prefix alone that the
near pointers we are passing to an instruction are valid pointers in
the segment currently contained in the segment register.

In terms of our actual classes: We don't know from a SyscallInterface
alone that the identifiers we are passing to a syscall match the
namespaces active in the task behind the SyscallInterface.

(The task is like the segment register, in this analogy.)

"""

from __future__ import annotations
import trio
import typing as t

# re-exported namepsace-local identifiers
from rsyscall.near.types import (
    FileDescriptor,
    WatchDescriptor,
    Address,
    MemoryMapping,
    Process,
    ProcessGroup,
)
# re-exported SyscallInterface
from rsyscall.near.sysif import SyscallInterface, SyscallResponse, SyscallHangup

from rsyscall.sys.syscall import SYS

from rsyscall.fcntl import AT, F
from rsyscall.sys.wait import IdType
from rsyscall.sys.prctl import PR
from rsyscall.sys.socket import SHUT
from rsyscall.sys.uio import RWF
from rsyscall.sched import CLONE
from rsyscall.signal import HowSIG, SIG

#### Syscalls (instructions)
# These are like instructions, run with this segment register override prefix and arguments.
import trio

async def accept4(sysif: SyscallInterface, sockfd: FileDescriptor,
                  addr: t.Optional[Address], addrlen: t.Optional[Address], flags: int) -> FileDescriptor:
    if addr is None:
        addr = 0 # type: ignore
    if addrlen is None:
        addrlen = 0 # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.accept4, sockfd, addr, addrlen, flags))

async def bind(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: int) -> None:
    await sysif.syscall(SYS.bind, sockfd, addr, addrlen)

async def capget(sysif: SyscallInterface, hdrp: Address, datap: Address) -> None:
    await sysif.syscall(SYS.capget, hdrp, datap)

async def capset(sysif: SyscallInterface, hdrp: Address, datap: Address) -> None:
    await sysif.syscall(SYS.capset, hdrp, datap)

async def chdir(sysif: SyscallInterface, path: Address) -> None:
    await sysif.syscall(SYS.chdir, path)

async def clone(sysif: SyscallInterface, flags: int, child_stack: Address,
                ptid: t.Optional[Address], ctid: t.Optional[Address],
                newtls: t.Optional[Address]) -> Process:
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

async def close(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    await sysif.syscall(SYS.close, fd)

async def connect(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: int) -> None:
    await sysif.syscall(SYS.connect, sockfd, addr, addrlen)

async def dup3(sysif: SyscallInterface, oldfd: FileDescriptor, newfd: FileDescriptor, flags: int) -> None:
    await sysif.syscall(SYS.dup3, oldfd, newfd, flags)

async def execve(sysif: SyscallInterface,
                 path: Address, argv: Address, envp: Address) -> None:
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execve, path, argv, envp)

async def execveat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Address,
                   argv: Address, envp: Address, flags: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execveat, dirfd, path, argv, envp, flags)

async def exit(sysif: SyscallInterface, status: int) -> None:
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.exit, status)

async def faccessat(sysif: SyscallInterface,
                    dirfd: t.Optional[FileDescriptor], path: Address, flags: int, mode: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.faccessat, dirfd, path, flags, mode)

async def fchdir(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    await sysif.syscall(SYS.fchdir, fd)

async def fchmod(sysif: SyscallInterface, fd: FileDescriptor, mode: int) -> None:
    await sysif.syscall(SYS.fchmod, fd, mode)

async def fcntl(sysif: SyscallInterface, fd: FileDescriptor, cmd: F, arg: t.Optional[t.Union[int, Address]]=None) -> int:
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.fcntl, fd, cmd, arg))

async def ftruncate(sysif: SyscallInterface, fd: FileDescriptor, length: int) -> None:
    await sysif.syscall(SYS.ftruncate, fd, length)

async def getdents64(sysif: SyscallInterface, fd: FileDescriptor, dirp: Address, count: int) -> int:
    return (await sysif.syscall(SYS.getdents64, fd, dirp, count))

async def getgid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getgid))

async def getpeername(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: Address) -> None:
    await sysif.syscall(SYS.getpeername, sockfd, addr, addrlen)

async def getpgid(sysif: SyscallInterface, pid: t.Optional[Process]) -> ProcessGroup:
    if pid is None:
        pid = 0 # type: ignore
    return ProcessGroup(await sysif.syscall(SYS.getpgid, pid))

async def getsockname(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: Address) -> None:
    await sysif.syscall(SYS.getsockname, sockfd, addr, addrlen)

async def getsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int, optval: Address, optlen: Address) -> None:
    await sysif.syscall(SYS.getsockopt, sockfd, level, optname, optval, optlen)

async def getuid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getuid))

async def ioctl(sysif: SyscallInterface, fd: FileDescriptor, request: int,
                arg: t.Optional[t.Union[int, Address]]=None) -> int:
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.ioctl, fd, request, arg))

async def kill(sysif: SyscallInterface, pid: t.Union[Process, ProcessGroup], sig: SIG) -> None:
    if isinstance(pid, ProcessGroup):
        pid = -int(pid) # type: ignore
    await sysif.syscall(SYS.kill, pid, sig)

async def linkat(sysif: SyscallInterface,
                 olddirfd: t.Optional[FileDescriptor], oldpath: Address,
                 newdirfd: t.Optional[FileDescriptor], newpath: Address,
                 flags: int) -> None:
    if olddirfd is None:
        olddirfd = AT.FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.linkat, olddirfd, oldpath, newdirfd, newpath, flags)

async def listen(sysif: SyscallInterface, sockfd: FileDescriptor, backlog: int) -> None:
    await sysif.syscall(SYS.listen, sockfd, backlog)

async def lseek(sysif: SyscallInterface, fd: FileDescriptor, offset: int, whence: int) -> int:
    return (await sysif.syscall(SYS.lseek, fd, offset, whence))

async def mkdirat(sysif: SyscallInterface,
                  dirfd: t.Optional[FileDescriptor], path: Address, mode: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.mkdirat, dirfd, path, mode)

async def mount(sysif: SyscallInterface, source: Address, target: Address,
                filesystemtype: Address, mountflags: int,
                data: Address) -> None:
    await sysif.syscall(SYS.mount, source, target, filesystemtype, mountflags, data)

async def openat(sysif: SyscallInterface, dirfd: t.Optional[FileDescriptor],
                 path: Address, flags: int, mode: int) -> FileDescriptor:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.openat, dirfd, path, flags, mode))

async def pipe2(sysif: SyscallInterface, pipefd: Address, flags: int) -> None:
    await sysif.syscall(SYS.pipe2, pipefd, flags)

async def prctl(sysif: SyscallInterface, option: PR, arg2: int,
                arg3: t.Optional[int], arg4: t.Optional[int], arg5: t.Optional[int]) -> int:
    if arg3 is None:
        arg3 = 0
    if arg4 is None:
        arg4 = 0
    if arg5 is None:
        arg5 = 0
    return (await sysif.syscall(SYS.prctl, option, arg2, arg3, arg4, arg5))

async def pread(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int, offset: int) -> int:
    return (await sysif.syscall(SYS.pread64, fd, buf, count, offset))

async def preadv2(sysif: SyscallInterface, fd: FileDescriptor, iov: Address, iovcnt: int, offset: int, flags: RWF) -> int:
    return (await sysif.syscall(SYS.preadv2, fd, iov, iovcnt, offset, flags))

async def pwritev2(sysif: SyscallInterface, fd: FileDescriptor, iov: Address, iovcnt: int, offset: int, flags: RWF) -> int:
    return (await sysif.syscall(SYS.pwritev2, fd, iov, iovcnt, offset, flags))

async def read(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int) -> int:
    return (await sysif.syscall(SYS.read, fd, buf, count))

async def readlinkat(sysif: SyscallInterface,
                     dirfd: t.Optional[FileDescriptor], path: Address,
                     buf: Address, bufsiz: int) -> int:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return (await sysif.syscall(SYS.readlinkat, dirfd, path, buf, bufsiz))

async def recv(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int, flags: int) -> int:
    return (await sysif.syscall(SYS.recvfrom, fd, buf, count, flags))

async def recvmsg(sysif: SyscallInterface, fd: FileDescriptor, msg: Address, flags: int) -> int:
    return (await sysif.syscall(SYS.recvmsg, fd, msg, flags))

async def renameat2(sysif: SyscallInterface,
                    olddirfd: t.Optional[FileDescriptor], oldpath: Address,
                    newdirfd: t.Optional[FileDescriptor], newpath: Address,
                    flags: int) -> None:
    if olddirfd is None:
        olddirfd = AT.FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.renameat2, olddirfd, oldpath, newdirfd, newpath, flags)

async def rt_sigaction(sysif: SyscallInterface, signum: SIG,
                       act: t.Optional[Address],
                       oldact: t.Optional[Address],
                       size: int) -> None:
    if act is None:
        act = 0 # type: ignore
    if oldact is None:
        oldact = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigaction, signum, act, oldact, size)

async def sendmsg(sysif: SyscallInterface, fd: FileDescriptor, msg: Address, flags: int) -> int:
    return (await sysif.syscall(SYS.sendmsg, fd, msg, flags))

async def set_robust_list(sysif: SyscallInterface, head: Address, len: int) -> None:
    await sysif.syscall(SYS.set_robust_list, head, len)

async def set_tid_address(sysif: SyscallInterface, ptr: Address) -> None:
    await sysif.syscall(SYS.set_tid_address, ptr)

async def setns(sysif: SyscallInterface, fd: FileDescriptor, nstype: int) -> None:
    await sysif.syscall(SYS.setns, fd, nstype)

async def setpgid(sysif: SyscallInterface, pid: t.Optional[Process], pgid: t.Optional[ProcessGroup]) -> None:
    if pid is None:
        pid = 0 # type: ignore
    if pgid is None:
        pgid = 0 # type: ignore
    await sysif.syscall(SYS.setpgid, pid, pgid)

async def setsid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.setsid))

async def setsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int,
                     optval: Address, optlen: int) -> None:
    await sysif.syscall(SYS.setsockopt, sockfd, level, optname, optval, optlen)

async def shutdown(sysif: SyscallInterface, sockfd: FileDescriptor, how: SHUT) -> None:
    await sysif.syscall(SYS.shutdown, sockfd, how)

async def socket(sysif: SyscallInterface, domain: int, type: int, protocol: int) -> FileDescriptor:
    return FileDescriptor(await sysif.syscall(SYS.socket, domain, type, protocol))

async def socketpair(sysif: SyscallInterface, domain: int, type: int, protocol: int, sv: Address) -> None:
    await sysif.syscall(SYS.socketpair, domain, type, protocol, sv)

async def symlinkat(sysif: SyscallInterface,
                    target: Address, newdirfd: t.Optional[FileDescriptor], linkpath: Address) -> None:
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.symlinkat, target, newdirfd, linkpath)

async def unlinkat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Address, flags: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.unlinkat, dirfd, path, flags)

async def unshare(sysif: SyscallInterface, flags: CLONE) -> None:
    await sysif.syscall(SYS.unshare, flags)

async def waitid(sysif: SyscallInterface,
                 id: t.Union[Process, ProcessGroup, None], infop: t.Optional[Address], options: int,
                 rusage: t.Optional[Address]) -> int:
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

async def write(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int) -> int:
    return (await sysif.syscall(SYS.write, fd, buf, count))

