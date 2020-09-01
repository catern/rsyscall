"Modeled after unistd.h."
from __future__ import annotations
from rsyscall._raw import lib # type: ignore
import enum
import typing as t

__all__ = [
    "SEEK",
    "IOFileDescriptor",
    "SeekableFileDescriptor",
]

class SEEK(enum.IntEnum):
    "The whence argument to lseek."
    SET = lib.SEEK_SET
    CUR = lib.SEEK_CUR
    END = lib.SEEK_END
    DATA = lib.SEEK_DATA
    HOLE = lib.SEEK_HOLE

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask
from rsyscall.handle.pointer import Pointer, WrittenPointer
from rsyscall.path import Path, EmptyPath

class IOFileDescriptor(BaseFileDescriptor):
    async def read(self, buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        """read from a file descriptor

        manpage: read(2)
        """
        self._validate()
        buf.check_address_space(self.task)
        ret = await _read(self.task.sysif, self.near, buf.near, buf.size())
        return buf.split(ret)

    async def write(self, buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        """write to a file descriptor

        manpage: write(2)
        """
        self._validate()
        buf.check_address_space(self.task)
        ret = await _write(self.task.sysif, self.near, buf.near, buf.size())
        return buf.split(ret)

class SeekableFileDescriptor(IOFileDescriptor):
    async def pread(self, buf: Pointer, offset: int) -> t.Tuple[Pointer, Pointer]:
        self._validate()
        with buf.borrow(self.task):
            ret = await _pread(self.task.sysif, self.near, buf.near, buf.size(), offset)
            return buf.split(ret)

    async def pwrite(self, buf: Pointer, offset: int) -> t.Tuple[Pointer, Pointer]:
        self._validate()
        with buf.borrow(self.task):
            ret = await _pwrite(self.task.sysif, self.near, buf.near, buf.size(), offset)
            return buf.split(ret)

    async def lseek(self, offset: int, whence: SEEK) -> int:
        self._validate()
        return (await _lseek(self.task.sysif, self.near, offset, whence))

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _read(sysif: SyscallInterface, fd: near.FileDescriptor,
                buf: near.Address, count: int) -> int:
    return (await sysif.syscall(SYS.read, fd, buf, count))

async def _write(sysif: SyscallInterface, fd: near.FileDescriptor,
                 buf: near.Address, count: int) -> int:
    return (await sysif.syscall(SYS.write, fd, buf, count))

async def _pread(sysif: SyscallInterface, fd: near.FileDescriptor,
                 buf: near.Address, count: int, offset: int) -> int:
    return (await sysif.syscall(SYS.pread64, fd, buf, count, offset))

async def _pwrite(sysif: SyscallInterface, fd: near.FileDescriptor,
                  buf: near.Address, count: int, offset: int) -> int:
    return (await sysif.syscall(SYS.pwrite64, fd, buf, count, offset))

async def _lseek(sysif: SyscallInterface, fd: near.FileDescriptor,
                 offset: int, whence: SEEK) -> int:
    return (await sysif.syscall(SYS.lseek, fd, offset, whence))
