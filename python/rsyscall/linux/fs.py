"`#include <linux/fs.h>`"
from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct
import dataclasses
import enum
import typing as t
if t.TYPE_CHECKING:
    from rsyscall.handle import FileDescriptor
else:
    FileDescriptor = object

class FI(enum.IntEnum):
    CLONERANGE = lib.FICLONERANGE
    CLONE = lib.FICLONE

@dataclasses.dataclass
class FileCloneRange(Struct):
    src_fd: FileDescriptor
    src_offset: int
    src_length: int
    dest_offset: int

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct file_clone_range const*', {
            "src_fd": self.src_fd,
            "src_offset": self.src_offset,
            "src_length": self.src_length,
            "dest_offset": self.dest_offset,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct file_clone_range')
