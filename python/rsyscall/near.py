from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import enum
import abc
import logging
import typing as t
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class SYS(enum.IntEnum):
    read = lib.SYS_read
    write = lib.SYS_write
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

# This is like the segment register override prefix, with no awareness of the contents of the register.
class SyscallInterface:
    # Throws on negative return value
    @abc.abstractmethod
    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int: ...
    # non-syscall operations which we haven't figured out how to get rid of yet
    @abc.abstractmethod
    async def close_interface(self) -> None: ...
    # when this file descriptor is readable, it means other things want to run on this thread.
    # Users of the SyscallInterface should ensure that when they block, they are monitoring this fd as well.
    # Typically, this is in fact the fd which the rsyscall server reads for incoming system calls!
    activity_fd: t.Optional[FileDescriptor]

# This is like a near pointer.
@dataclass
class FileDescriptor:
    number: int

    def __str__(self) -> str:
        return f"FD({self.number})"

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

# This is like an instruction, run with this segment register override prefix and arguments.
async def read(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    return (await sysif.syscall(SYS.read, fd, buf, count))

async def write(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    return (await sysif.syscall(SYS.write, fd, buf, count))

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
