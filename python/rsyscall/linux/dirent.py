"""`#include <linux/dirent.h>`

Not actually mentioned in the manpage for getdents.

"""
from __future__ import annotations
from rsyscall._raw import lib, ffi # type: ignore
import typing as t
import enum
from dataclasses import dataclass
from rsyscall.struct import Serializable

__all__ = [
    "DT",
    "Dirent",
    "DirentList",
    "GetdentsFileDescriptor",
]

class DT(enum.IntEnum):
    BLK = lib.DT_BLK # This is a block device.
    CHR = lib.DT_CHR # This is a character device.
    DIR = lib.DT_DIR # This is a directory.
    FIFO = lib.DT_FIFO # This is a named pipe (FIFO).
    LNK = lib.DT_LNK # This is a symbolic link.
    REG = lib.DT_REG # This is a regular file.
    SOCK = lib.DT_SOCK # This is a UNIX domain socket.
    UNKNOWN = lib.DT_UNKNOWN # The file type is unknown.

_d_name_offset = ffi.offsetof('struct linux_dirent64', 'd_name')

@dataclass
class Dirent:
    inode: int
    offset: int # the offset to seek to to see the next dirent
    type: DT
    name: str

    def __str__(self) -> str:
        return f"Dirent({self.type}, {self.name})"

    def to_bytes(self) -> bytes:
        def record(reclen: int) -> bytes:
            record = ffi.new('struct linux_dirent64*', {
                "d_ino": self.inode,
                "d_off": self.offset,
                "d_reclen": reclen,
                "d_type": self.type,
                "d_name": self.name.encode(),
            })
            data = bytes(ffi.buffer(record))
            # pad to real length
            return data + bytes(8 - (len(data) % 8))
        return record(len(record(0)))

class DirentList(t.List[Dirent], Serializable):
    def to_bytes(self) -> bytes:
        ret = b""
        for ent in self:
            ret += ent.to_bytes()
        return ret

    T = t.TypeVar('T', bound='DirentList')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        entries = []
        while len(data) > 0:
            # We do the work of from_bytes in this class instead of in Dirent because we need the
            # raw length field from the struct; merely doing len(name) will exclude padding.
            record = ffi.cast('struct linux_dirent64*', ffi.from_buffer(data))
            name_len = record.d_reclen - _d_name_offset
            # the name is padded with null bytes to make the dirent aligned,
            # so we have to use strlen to find the end
            name = ffi.string(record.d_name, name_len).decode()
            entries.append(Dirent(inode=record.d_ino, offset=record.d_off, type=DT(record.d_type), name=name))
            data = data[record.d_reclen:]
        return cls(entries)

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor
from rsyscall.handle.pointer import Pointer, ReadablePointer

class GetdentsFileDescriptor(BaseFileDescriptor):
    async def getdents(self, dirp: Pointer[DirentList]) -> t.Tuple[ReadablePointer[DirentList], Pointer]:
        self._validate()
        with dirp.borrow(self.task) as dirp_n:
            ret = await _getdents64(self.task.sysif, self.near, dirp_n, dirp.size())
            return dirp.readable_split(ret)

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _getdents64(sysif: SyscallInterface, fd: near.FileDescriptor,
                      dirp: near.Address, count: int) -> int:
    return (await sysif.syscall(SYS.getdents64, fd, dirp, count))


#### Tests ####
from unittest import TestCase

class TestDirent(TestCase):
    def test_dirent(self) -> None:
        original = DirentList([Dirent(0, 1, DT.UNKNOWN, "hello"),
                               Dirent(124, 914, DT.SOCK, "hello"*512),
                               Dirent(0, 1, DT.UNKNOWN, "hello")])
        ret = DirentList.from_bytes(original.to_bytes())
        self.assertEqual(original, ret)
