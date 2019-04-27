from __future__ import annotations
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import AF, Address, _register_sockaddr
from rsyscall.path import PathLike
from dataclasses import dataclass
import os

class PathTooLongError(ValueError):
    pass

@dataclass
class SockaddrUn(Address):
    path: bytes

    family = AF.UNIX
    def __post_init__(self) -> None:
        if len(self.path) > 108:
            raise PathTooLongError("path", self.path, "is longer than the maximum unix address size")

    @staticmethod
    def from_path(path: PathLike) -> SockaddrUn:
        return SockaddrUn(os.fsencode(path))

    T = t.TypeVar('T', bound='SockaddrUn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        header = ffi.sizeof('sa_family_t')
        if len(data) < header:
            raise Exception("data too smalllll", data)
        struct = ffi.cast('struct sockaddr_un*', ffi.from_buffer(data))
        cls.check_family(AF(struct.sun_family))
        if len(data) == header:
            # unnamed socket, name is empty
            # fffffff FFFFFFFFFFF FUUUUUUUUUUUUUUUUUUUUUUUU
            # UFCK
            # okay so... is there a way to figure this out without looking at socklen
            # fuuuu
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
        addr = ffi.new('struct sockaddr_un*', (AF.UNIX, self.path))
        real_length = ffi.sizeof('sa_family_t') + len(self.path) + 1
        return bytes(ffi.buffer(addr))[:real_length]

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_un')

    def __str__(self) -> str:
        return f"SockaddrUn({self.path})"
_register_sockaddr(SockaddrUn)


#### Tests ####
from unittest import TestCase
class TestUn(TestCase):
    def test_sockaddrun(self) -> None:
        initial = SockaddrUn(b"asefliasjeflsaifje0.1")
        output = SockaddrUn.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
        from rsyscall.sys.socket import GenericSockaddr
        out = GenericSockaddr.from_bytes(initial.to_bytes()).parse()
        self.assertEqual(initial, output)
        