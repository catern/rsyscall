"Modeled after unistd.h."
from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import enum
from rsyscall.struct import Serializer, FixedSerializer, Serializable, FixedSize
import struct
import typing as t
import rsyscall.near.types as near
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer, Task, FileDescriptor
else:
    Pointer = t.Optional

__all__ = [
    "SEEK",
    "OK",
    "Arg",
    "ArgList"
    "Pipe",
]

class SEEK(enum.IntEnum):
    "The whence argument to lseek."
    SET = lib.SEEK_SET
    CUR = lib.SEEK_CUR
    END = lib.SEEK_END
    DATA = lib.SEEK_DATA
    HOLE = lib.SEEK_HOLE

class OK(enum.IntFlag):
    "The mode argument to access, faccessat."
    R = lib.R_OK
    W = lib.W_OK
    X = lib.X_OK
    F = lib.F_OK

class Arg(bytes, Serializable):
    "A null-terminated string, as passed to execve."
    def to_bytes(self) -> bytes:
        return self + b'\0'

    T = t.TypeVar('T', bound='Arg')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        try:
            nullidx = data.index(b'\0')
        except ValueError:
            return cls(data)
        else:
            return cls(data[0:nullidx])

T_arglist = t.TypeVar('T_arglist', bound='ArgList')
class ArgList(t.List[Pointer[Arg]], FixedSerializer):
    "A null-terminated list of null-terminated strings, as passed to execve."
    @classmethod
    def get_serializer(cls, task: Task) -> Serializer[T_arglist]:
        return ArgListSerializer()

import struct
class ArgListSerializer(Serializer[T_arglist]):
    def to_bytes(self, arglist: T_arglist) -> bytes:
        ret = b""
        for ptr in arglist:
            ret += struct.Struct("Q").pack(int(ptr.near))
        ret += struct.Struct("Q").pack(0)
        return ret

    def from_bytes(self, data: bytes) -> T_arglist:
        raise Exception("can't get pointer handles from raw bytes")


#### pipe stuff

T_pipe = t.TypeVar('T_pipe', bound='Pipe')
@dataclass
class Pipe(FixedSize):
    "A pair of file descriptors, as written by pipe."
    read: FileDescriptor
    write: FileDescriptor

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fdpair')

    @classmethod
    def get_serializer(cls: t.Type[T_pipe], task: Task) -> Serializer[T_pipe]:
        return PipeSerializer(cls, task)

@dataclass
class PipeSerializer(Serializer[T_pipe]):
    cls: t.Type[T_pipe]
    task: Task

    def to_bytes(self, pair: T_pipe) -> bytes:
        struct = ffi.new('struct fdpair*', (pair.read, pair.write))
        return bytes(ffi.buffer(struct))

    def from_bytes(self, data: bytes) -> T_pipe:
        struct = ffi.cast('struct fdpair const*', ffi.from_buffer(data))
        def make(n: int) -> FileDescriptor:
            return self.task.make_fd_handle(near.FileDescriptor(int(n)))
        return self.cls(make(struct.first), make(struct.second))

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask
from rsyscall.handle.pointer import Pointer, WrittenPointer
from rsyscall.path import Path, EmptyPath

class IOFileDescriptor(BaseFileDescriptor):
    async def read(self, buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        self._validate()
        with buf.borrow(self.task) as buf_n:
            ret = await _read(self.task.sysif, self.near, buf_n, buf.size())
            return buf.split(ret)

    async def write(self, buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        self._validate()
        with buf.borrow(self.task) as buf_n:
            ret = await _write(self.task.sysif, self.near, buf_n, buf.size())
            return buf.split(ret)

class SeekableFileDescriptor(IOFileDescriptor):
    async def pread(self, buf: Pointer, offset: int) -> t.Tuple[Pointer, Pointer]:
        self._validate()
        with buf.borrow(self.task):
            ret = await _pread(self.task.sysif, self.near, buf.near, buf.size(), offset)
            return buf.split(ret)

    async def lseek(self, offset: int, whence: SEEK) -> int:
        self._validate()
        return (await _lseek(self.task.sysif, self.near, offset, whence))

from rsyscall.fcntl import AT, O
T_fd = t.TypeVar('T_fd', bound='FSFileDescriptor')
class FSFileDescriptor(BaseFileDescriptor):
    async def readlinkat(self, path: t.Union[WrittenPointer[Path], WrittenPointer[EmptyPath]],
                         buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        self._validate()
        with path.borrow(self.task):
            with buf.borrow(self.task):
                ret = await _readlinkat(self.task.sysif, self.near, path.near, buf.near, buf.size())
                return buf.split(ret)

    async def faccessat(self, ptr: WrittenPointer[Path], mode: OK, flags: AT=AT.NONE) -> None:
        self._validate()
        with ptr.borrow(self.task):
            await _faccessat(self.task.sysif, self.near, ptr.near, mode, flags)

    async def openat(self: T_fd, path: WrittenPointer[Path], flags: O, mode=0o644) -> T_fd:
        self._validate()
        with path.borrow(self.task) as path_n:
            fd = await _openat(self.task.sysif, self.near, path_n, flags|O.CLOEXEC, mode)
            return self.task.make_fd_handle(fd)

    async def fchmod(self, mode: int) -> None:
        self._validate()
        await _fchmod(self.task.sysif, self.near, mode)

    async def ftruncate(self, length: int) -> None:
        self._validate()
        await _ftruncate(self.task.sysif, self.near, length)

class FSTask(t.Generic[T_fd], FileDescriptorTask[T_fd]):
    async def readlink(self, path: WrittenPointer[Path], buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        with path.borrow(self) as path_n:
            with buf.borrow(self) as buf_n:
                ret = await _readlinkat(self.sysif, None, path_n, buf_n, buf.size())
                return buf.split(ret)

    async def access(self, path: WrittenPointer[Path], mode: int, flags: int=0) -> None:
        with path.borrow(self) as path_n:
            try:
                await _faccessat(self.sysif, None, path_n, mode, flags)
            except FileNotFoundError as exn:
                exn.filename = path.value
                raise

    async def open(self, path: WrittenPointer[Path], flags: O, mode=0o644) -> T_fd:
        with path.borrow(self) as path_n:
            try:
                fd = await _openat(self.sysif, None, path_n, flags|O.CLOEXEC, mode)
            except FileNotFoundError as exn:
                exn.filename = path.value
                raise
            return self.make_fd_handle(fd)

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

async def _lseek(sysif: SyscallInterface, fd: near.FileDescriptor,
                 offset: int, whence: SEEK) -> int:
    return (await sysif.syscall(SYS.lseek, fd, offset, whence))

async def _readlinkat(sysif: SyscallInterface, dirfd: t.Optional[near.FileDescriptor],
                      path: near.Address, buf: near.Address, bufsiz: int) -> int:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return (await sysif.syscall(SYS.readlinkat, dirfd, path, buf, bufsiz))

async def _faccessat(sysif: SyscallInterface, dirfd: t.Optional[near.FileDescriptor],
                     path: near.Address, flags: int, mode: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.faccessat, dirfd, path, flags, mode)

async def _openat(sysif: SyscallInterface, dirfd: t.Optional[near.FileDescriptor],
                  path: near.Address, flags: int, mode: int) -> near.FileDescriptor:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return near.FileDescriptor(await sysif.syscall(SYS.openat, dirfd, path, flags, mode))

async def _fchmod(sysif: SyscallInterface, fd: near.FileDescriptor, mode: int) -> None:
    await sysif.syscall(SYS.fchmod, fd, mode)

async def _ftruncate(sysif: SyscallInterface, fd: near.FileDescriptor, length: int) -> None:
    await sysif.syscall(SYS.ftruncate, fd, length)
