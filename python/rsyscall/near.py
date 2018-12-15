from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import socket
import struct
import os
import enum
import abc
import logging
import typing as t
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class SYS(enum.IntEnum):
    read = lib.SYS_read
    write = lib.SYS_write
    recvfrom = lib.SYS_recvfrom
    close = lib.SYS_close
    fcntl = lib.SYS_fcntl
    sendmsg = lib.SYS_sendmsg
    recvmsg = lib.SYS_recvmsg
    dup3 = lib.SYS_dup3
    accept4 = lib.SYS_accept4
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

class IdType(enum.IntEnum):
    PID = lib.P_PID # Wait for the child whose process ID matches id.
    PGID = lib.P_PGID # Wait for any child whose process group ID matches id.
    ALL = lib.P_ALL # Wait for any child; id is ignored.

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
    activity_fd: t.Optional[FileDescriptor]
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

# This is like the actual memory. Not sure what to think of this.
@dataclass(eq=False)
class File:
    pass

class DirectoryFile(File):
    pass

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

async def recv(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int, flags: int) -> int:
    return (await sysif.syscall(SYS.recvfrom, fd, buf, count, flags))

async def close(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    await sysif.syscall(SYS.close, fd)

async def fcntl(sysif: SyscallInterface, fd: FileDescriptor, cmd: int, arg: t.Optional[t.Union[int, Pointer]]=None) -> int:
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
                  addr: t.Optional[Pointer], addrlen: t.Optional[Pointer], flags: int) -> int:
    if addr is None:
        addr = 0 # type: ignore
    if addrlen is None:
        addrlen = 0 # type: ignore
    return (await sysif.syscall(SYS.accept4, sockfd, addr, addrlen, flags))

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

async def unshare(sysif: SyscallInterface, flags: UnshareFlag) -> None:
    await sysif.syscall(SYS.unshare, flags)

class EpollCtlOp(enum.IntEnum):
    ADD = lib.EPOLL_CTL_ADD
    MOD = lib.EPOLL_CTL_MOD
    DEL = lib.EPOLL_CTL_DEL

async def epoll_ctl(sysif: SyscallInterface, epfd: FileDescriptor, op: EpollCtlOp,
                    fd: FileDescriptor, event: t.Optional[Pointer]=None) -> None:
    if event is None:
        event = 0 # type: ignore
    await sysif.syscall(SYS.epoll_ctl, epfd, op, fd, event)

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
