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

    def __int__(self) -> int:
        return self.address

# This is like an instruction, run with this segment register override prefix and arguments.
async def read(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    return (await sysif.syscall(SYS.read, fd, buf, count))

async def write(sysif: SyscallInterface, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    return (await sysif.syscall(SYS.write, fd, buf, count))

