from __future__ import annotations
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import Address
from rsyscall.path import PathLike
import os

class PathTooLongError(ValueError):
    pass

class SockaddrUn(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_un')
    def __init__(self, path: bytes) -> None:
        if len(path) > 108:
            raise PathTooLongError("path is longer than the maximum unix address size")
        self.path = path

    @staticmethod
    def from_path(path: PathLike) -> SockaddrUn:
        return SockaddrUn(os.fsencode(path))

    T = t.TypeVar('T', bound='SockaddrUn')
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
        return f"SockaddrUn({self.path})"
