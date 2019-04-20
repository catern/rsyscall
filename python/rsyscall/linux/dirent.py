from __future__ import annotations
from rsyscall._raw import lib, ffi # type: ignore
import typing as t
import enum
from dataclasses import dataclass

class DT(enum.Enum):
    BLK = lib.DT_BLK # This is a block device.
    CHR = lib.DT_CHR # This is a character device.
    DIR = lib.DT_DIR # This is a directory.
    FIFO = lib.DT_FIFO # This is a named pipe (FIFO).
    LNK = lib.DT_LNK # This is a symbolic link.
    REG = lib.DT_REG # This is a regular file.
    SOCK = lib.DT_SOCK # This is a UNIX domain socket.
    UNKNOWN = lib.DT_UNKNOWN # The file type is unknown.

@dataclass
class Dirent:
    inode: int
    offset: int # the offset to seek to to see the next dirent
    type: DT
    name: bytes

    def __str__(self) -> str:
        return f"Dirent({self.type}, {self.name})"

    @classmethod
    def list_from_bytes(cls, data: bytes) -> t.List[Dirent]:
        entries = []
        while len(data) > 0:
            record = ffi.cast('struct linux_dirent64*', ffi.from_buffer(data))
            # the name is padded with null bytes to make the dirent
            # aligned, so we have to use strlen to find the end
            name_size = lib.strlen(record.d_name)
            name = bytes(ffi.buffer(record.d_name, name_size))
            entries.append(Dirent(inode=record.d_ino, offset=record.d_off, type=DT(record.d_type), name=name))
            data = data[record.d_reclen:]
        return entries
