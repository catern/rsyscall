from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import os
import typing as t
import logging
import abc
import socket
import struct
import enum
import signal
import ipaddress
from rsyscall.far import AddressSpace, FDTable, Pointer, Path
from rsyscall.far import Process, ProcessGroup, FileDescriptor
from rsyscall.handle import Task
from rsyscall.near import SyscallInterface
from rsyscall.exceptions import RsyscallException, RsyscallHangup
from rsyscall.struct import Struct
import rsyscall.far
import rsyscall.near

# Here we have base dataclasses which don't carry around references to a task.
# In particular, Pointer, FileDescriptor, and Path all should be in here,
# without a reference to a task.
# These things are all "far pointers" in terms of memory segmentation.

# The ones in io.py carry a reference to a Task, and so are more convenient for users.

class MemoryWriter:
    @abc.abstractmethod
    async def write(self, dest: Pointer, data: bytes) -> None: ...
    @abc.abstractmethod
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None: ...

class MemoryReader:
    @abc.abstractmethod
    async def read(self, src: Pointer, n: int) -> bytes: ...
    @abc.abstractmethod
    async def batch_read(self, ops: t.List[t.Tuple[Pointer, int]]) -> t.List[bytes]: ...

class MemoryTransport(MemoryWriter, MemoryReader):
    @abc.abstractmethod
    def inherit(self, task: Task) -> MemoryTransport: ...

local_address_space = AddressSpace(os.getpid())

class InvalidAddressSpaceError(Exception):
    pass

def memcpy(dest: Pointer, src: Pointer, n: int) -> None:
    neardest = local_address_space.to_near(dest)
    nearsrc = local_address_space.to_near(src)
    lib.memcpy(ffi.cast('void*', int(neardest)), ffi.cast('void*', int(nearsrc)), n)

def cffi_to_local_pointer(cffi_object) -> Pointer:
    return Pointer(local_address_space, rsyscall.near.Pointer(int(ffi.cast('long', cffi_object))))

def to_local_pointer(data: bytes) -> Pointer:
    return cffi_to_local_pointer(ffi.from_buffer(data))


T_addr = t.TypeVar('T_addr', bound='Address')
class Address(Struct):
    addrlen: int
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls: t.Type[T_addr], data: bytes) -> T_addr: ...
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...
    @classmethod
    @abc.abstractmethod
    def sizeof(cls) -> int: ...

    @classmethod
    def parse(cls: t.Type[T_addr], data: bytes) -> T_addr:
        return cls.from_bytes(data)

class PathTooLongError(ValueError):
    pass

class UnixAddress(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_un')
    def __init__(self, path: bytes) -> None:
        if len(path) > 108:
            raise PathTooLongError("path is longer than the maximum unix address size")
        self.path = path

    @staticmethod
    def from_path(self, path: rsyscall.far.Path) -> UnixAddress:
        return UnixAddress(os.fsencode(path))

    T = t.TypeVar('T', bound='UnixAddress')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        header = ffi.sizeof('sa_family_t')
        buf = ffi.from_buffer(data)
        if len(data) < header:
            raise Exception("data too smalllll", data)
        struct = ffi.cast('struct sockaddr_un*', buf)
        if struct.sun_family != lib.AF_UNIX:
            raise Exception("sun_family must be", lib.AF_UNIX, "is instead", header.sun_family)
        if len(data) == header:
            # unnamed socket, name is empty
            length = 0
        elif struct.sun_path[0] == b'\0':
            # abstract socket, entire buffer is part of path
            length = len(data) - header
        else:
            # TODO handle the case where there's no null terminator
            # pathname socket, path is null-terminated
            length = lib.strlen(struct.sun_path)
        return cls(bytes(ffi.buffer(struct.sun_path, length)))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_un*', (lib.AF_UNIX, self.path))
        real_length = ffi.sizeof('sa_family_t') + len(self.path) + 1
        return bytes(ffi.buffer(addr))[:real_length]

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_un')

    def __str__(self) -> str:
        return f"UnixAddress({self.path})"

class SockaddrIn(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_in')
    def __init__(self, port: int, addr: t.Union[int, ipaddress.IPv4Address]) -> None:
        # these are in host byte order, of course
        self.port = port
        self.addr = ipaddress.IPv4Address(addr)

    T = t.TypeVar('T', bound='SockaddrIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct sockaddr_in*', ffi.from_buffer(data))
        if struct.sin_family != lib.AF_INET:
            raise Exception("sin_family must be", lib.AF_INET, "is instead", struct.sin_family)
        return cls(socket.ntohs(struct.sin_port), socket.ntohl(struct.sin_addr.s_addr))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_in*', (lib.AF_INET, socket.htons(self.port), (socket.htonl(int(self.addr)),)))
        return ffi.buffer(addr)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_in')

    def addr_as_string(self) -> str:
        "Returns the addr portion of this address in 127.0.0.1 form"
        return str(self.addr)

    def __str__(self) -> str:
        return f"SockaddrIn({self.addr_as_string()}:{self.port})"

InetAddress = SockaddrIn

class IdType(enum.IntEnum):
    PID = lib.P_PID # Wait for the child whose process ID matches id.
    PGID = lib.P_PGID # Wait for any child whose process group ID matches id.
    ALL = lib.P_ALL # Wait for any child; id is ignored.

class EpollCtlOp(enum.IntEnum):
    ADD = lib.EPOLL_CTL_ADD
    MOD = lib.EPOLL_CTL_MOD
    DEL = lib.EPOLL_CTL_DEL

class ChildCode(enum.Enum):
    EXITED = lib.CLD_EXITED # child called _exit(2)
    KILLED = lib.CLD_KILLED # child killed by signal
    DUMPED = lib.CLD_DUMPED # child killed by signal, and dumped core
    STOPPED = lib.CLD_STOPPED # child stopped by signal
    TRAPPED = lib.CLD_TRAPPED # traced child has trapped
    CONTINUED = lib.CLD_CONTINUED # child continued by SIGCONT

class UncleanExit(Exception):
    pass

@dataclass
class ChildEvent:
    code: ChildCode
    pid: int
    uid: int
    exit_status: t.Optional[int]
    sig: t.Optional[signal.Signals]

    @staticmethod
    def make(code: ChildCode, pid: int, uid: int, status: int):
        if code is ChildCode.EXITED:
            return ChildEvent(code, pid, uid, status, None)
        else:
            return ChildEvent(code, pid, uid, None, signal.Signals(status))

    def died(self) -> bool:
        return self.code in [ChildCode.EXITED, ChildCode.KILLED, ChildCode.DUMPED]
    def clean(self) -> bool:
        return self.code == ChildCode.EXITED and self.exit_status == 0

    def check(self) -> None:
        if self.clean():
            return None
        else:
            raise UncleanExit(self)

    def killed_with(self) -> signal.Signals:
        """What signal was the child killed with?

        Throws if the child was not killed with a signal.

        """
        if not self.died():
            raise Exception("Child isn't dead")
        if self.sig is None:
            raise Exception("Child wasn't killed with a signal")
        return self.sig
