"`#include <sys/un.h>`"
from __future__ import annotations
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import AF, Sockaddr, _register_sockaddr
from rsyscall.path import Path
from dataclasses import dataclass
import os
from rsyscall.fcntl import O
if t.TYPE_CHECKING:
    from rsyscall.handle import FileDescriptor
    from rsyscall.thread import Thread

__all__ = [
    "PathTooLongError",
    "SockaddrUn",
]

class PathTooLongError(ValueError):
    pass

@dataclass
class SockaddrUn(Sockaddr):
    path: bytes

    family = AF.UNIX
    def __post_init__(self) -> None:
        if len(self.path) > 108:
            raise PathTooLongError("path", self.path, "is longer than the maximum unix address size")

    @staticmethod
    async def from_path(thr: Thread, path: t.Union[str, os.PathLike]) -> SockaddrUn:
        """Turn this path into a SockaddrUn, hacking around the 108 byte limit on socket addresses.

        If the passed path is too long to fit in an address, this function will open the parent
        directory with O_PATH and return SockaddrUn("/proc/self/fd/n/name").

        """
        try:
            return SockaddrUn(os.fsencode(path))
        except PathTooLongError:
            ppath = Path(path)
            fd = await thr.task.open(await thr.ram.ptr(ppath.parent), O.PATH)
            return SockaddrUnProcFd(fd, ppath.name)

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
        return f"SockaddrUn({self.path!r})"

    async def close(self) -> None:
        pass
_register_sockaddr(SockaddrUn)

class SockaddrUnProcFd(SockaddrUn):
    def __init__(self, fd: FileDescriptor, name: str) -> None:
        super().__init__(os.fsencode(f"/proc/self/fd/{int(fd)}/{name}"))
        self.fd = fd
        self.name = name

    async def close(self) -> None:
        await self.fd.close()


#### Tests ####
from unittest import TestCase
class TestUn(TestCase):
    def test_sockaddrun(self) -> None:
        initial = SockaddrUn(b"asefliasjeflsaifje0.1")
        output = SockaddrUn.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
        from rsyscall.sys.socket import SockaddrStorage
        out = SockaddrStorage.from_bytes(initial.to_bytes()).parse()
        self.assertEqual(initial, output)
        
