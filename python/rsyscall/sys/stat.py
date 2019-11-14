from __future__ import annotations
from dataclasses import dataclass
from rsyscall._raw import ffi # type: ignore
from rsyscall.handle.fd import BaseFileDescriptor
from rsyscall.handle.pointer import Pointer
from rsyscall.near.sysif import SyscallInterface
from rsyscall.struct import Struct, Serializable
from rsyscall.sys.syscall import SYS
from rsyscall.time import Timespec
import enum
import rsyscall.near.types as near
import typing as t

@dataclass
class Stat(Struct):
    dev: int
    mode: int
    nlink: int
    uid: int
    gid: int
    rdev: int
    size: int
    blksize: int
    blocks: int
    atime: Timespec
    mtime: Timespec
    ctime: Timespec

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct stat const*', {
            "st_dev": self.dev,
            "st_mode": self.mode,
            "st_nlink": self.nlink,
            "st_uid": self.uid,
            "st_gid": self.gid,
            "st_rdev": self.rdev,
            "st_size": self.size,
            "st_blksize": self.blksize,
            "st_blocks": self.blocks,
            "st_atim": self.atime._to_cffi_dict(),
            "st_mtim": self.mtime._to_cffi_dict(),
            "st_ctim": self.ctime._to_cffi_dict(),
        })))

    @property
    def atim(self) -> Timespec:
        return self.atime

    @property
    def mtim(self) -> Timespec:
        return self.mtime

    @property
    def ctim(self) -> Timespec:
        return self.ctime

    T = t.TypeVar('T', bound='Stat')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct stat*', ffi.from_buffer(data))
        return cls(
            dev=struct.st_dev,
            mode=struct.st_mode,
            nlink=struct.st_nlink,
            uid=struct.st_uid,
            gid=struct.st_gid,
            rdev=struct.st_rdev,
            size=struct.st_size,
            blksize=struct.st_blksize,
            blocks=struct.st_blocks,
            atime=Timespec.from_cffi(struct.st_atim),
            mtime=Timespec.from_cffi(struct.st_mtim),
            ctime=Timespec.from_cffi(struct.st_ctim),
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct stat')

async def _fstat(sysif: SyscallInterface, fd: near.FileDescriptor, statbuf: near.Address) -> None:
    await sysif.syscall(SYS.fstat, fd, statbuf)

class StatFileDescriptor(BaseFileDescriptor):
    async def fstat(self, statbuf: Pointer[Stat]) -> Pointer[Stat]:
        self._validate()
        with statbuf.borrow(self.task):
            await _fstat(self.task.sysif, self.near, statbuf.near)
        return statbuf
    

#### Tests ####
from unittest import TestCase
class TestStat(TestCase):
    def test_stat(self) -> None:
        initial = Stat(
            dev=0,
            mode=0,
            nlink=0,
            uid=0,
            gid=0,
            rdev=0,
            size=0,
            blksize=0,
            blocks=0,
            atime=Timespec(sec=0, nsec=0),
            mtime=Timespec(sec=0, nsec=0),
            ctime=Timespec(sec=0, nsec=0),
        )
        output = Stat.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
