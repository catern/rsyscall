"""`#include <linux/fuse.h>`

FUSE doesn't use unique prefixes for each set of flags. All the FUSE flags start with just "FUSE_"
instead of starting with, e.g., "FUSE_INIT_" for the flags used in the initialization message,
"FUSE_WRITE_" for the flags used in the write message, etc..

To follow this pattern in rsyscall, so that e.g. FUSE_ASYNC_READ was used as FUSE.ASYNC_READ, would
require one big enum for all the flags used in all the messages. This is not very type-safe, so we
make up separate enums for each set of flags. So FUSE_ASYNC_READ is FUSE_INIT.ASYNC_READ, etc..

"""
from __future__ import annotations
import abc
import enum
from dataclasses import dataclass
from rsyscall._raw import lib, ffi # type: ignore
from rsyscall.struct import Struct, Serializable, HasSerializer, Serializer
from rsyscall.unistd import O
from rsyscall.time import Timespec
from rsyscall.sys.stat import TypeMode
from rsyscall.linux.dirent import DT
from rsyscall.memory.allocator import align
from rsyscall import Path
import os
import typing as t


class FUSE_INIT(enum.IntFlag):
    NONE = 0
    ASYNC_READ = lib.FUSE_ASYNC_READ
    POSIX_LOCKS = lib.FUSE_POSIX_LOCKS
    FILE_OPS = lib.FUSE_FILE_OPS
    ATOMIC_O_TRUNC = lib.FUSE_ATOMIC_O_TRUNC
    EXPORT_SUPPORT = lib.FUSE_EXPORT_SUPPORT
    BIG_WRITES = lib.FUSE_BIG_WRITES
    DONT_MASK = lib.FUSE_DONT_MASK
    SPLICE_WRITE = lib.FUSE_SPLICE_WRITE
    SPLICE_MOVE = lib.FUSE_SPLICE_MOVE
    SPLICE_READ = lib.FUSE_SPLICE_READ
    FLOCK_LOCKS = lib.FUSE_FLOCK_LOCKS
    HAS_IOCTL_DIR = lib.FUSE_HAS_IOCTL_DIR
    AUTO_INVAL_DATA = lib.FUSE_AUTO_INVAL_DATA
    DO_READDIRPLUS = lib.FUSE_DO_READDIRPLUS
    READDIRPLUS_AUTO = lib.FUSE_READDIRPLUS_AUTO
    ASYNC_DIO = lib.FUSE_ASYNC_DIO
    WRITEBACK_CACHE = lib.FUSE_WRITEBACK_CACHE
    NO_OPEN_SUPPORT = lib.FUSE_NO_OPEN_SUPPORT
    PARALLEL_DIROPS = lib.FUSE_PARALLEL_DIROPS
    HANDLE_KILLPRIV = lib.FUSE_HANDLE_KILLPRIV
    POSIX_ACL = lib.FUSE_POSIX_ACL
    ABORT_ERROR = lib.FUSE_ABORT_ERROR

class FUSE_WRITE(enum.IntFlag):
    CACHE = lib.FUSE_WRITE_CACHE
    LOCKOWNER = lib.FUSE_WRITE_LOCKOWNER

class FUSE_RELEASE(enum.IntFlag):
    FLUSH = lib.FUSE_RELEASE_FLUSH
    FLOCK_UNLOCK = lib.FUSE_RELEASE_FLOCK_UNLOCK

class FUSE_OPCODE(enum.IntEnum):
    LOOKUP = lib.FUSE_LOOKUP
    FORGET = lib.FUSE_FORGET
    GETATTR = lib.FUSE_GETATTR
    SETATTR = lib.FUSE_SETATTR
    READLINK = lib.FUSE_READLINK
    SYMLINK = lib.FUSE_SYMLINK
    MKNOD = lib.FUSE_MKNOD
    MKDIR = lib.FUSE_MKDIR
    UNLINK = lib.FUSE_UNLINK
    RMDIR = lib.FUSE_RMDIR
    RENAME = lib.FUSE_RENAME
    LINK = lib.FUSE_LINK
    OPEN = lib.FUSE_OPEN
    READ = lib.FUSE_READ
    WRITE = lib.FUSE_WRITE
    STATFS = lib.FUSE_STATFS
    RELEASE = lib.FUSE_RELEASE
    FSYNC = lib.FUSE_FSYNC
    SETXATTR = lib.FUSE_SETXATTR
    GETXATTR = lib.FUSE_GETXATTR
    LISTXATTR = lib.FUSE_LISTXATTR
    REMOVEXATTR = lib.FUSE_REMOVEXATTR
    FLUSH = lib.FUSE_FLUSH
    INIT = lib.FUSE_INIT
    OPENDIR = lib.FUSE_OPENDIR
    READDIR = lib.FUSE_READDIR
    RELEASEDIR = lib.FUSE_RELEASEDIR
    FSYNCDIR = lib.FUSE_FSYNCDIR
    GETLK = lib.FUSE_GETLK
    SETLK = lib.FUSE_SETLK
    SETLKW = lib.FUSE_SETLKW
    ACCESS = lib.FUSE_ACCESS
    CREATE = lib.FUSE_CREATE
    INTERRUPT = lib.FUSE_INTERRUPT
    BMAP = lib.FUSE_BMAP
    DESTROY = lib.FUSE_DESTROY
    IOCTL = lib.FUSE_IOCTL
    POLL = lib.FUSE_POLL
    NOTIFY_REPLY = lib.FUSE_NOTIFY_REPLY
    BATCH_FORGET = lib.FUSE_BATCH_FORGET
    FALLOCATE = lib.FUSE_FALLOCATE
    READDIRPLUS = lib.FUSE_READDIRPLUS
    RENAME2 = lib.FUSE_RENAME2
    LSEEK = lib.FUSE_LSEEK

class FOPEN(enum.IntEnum):
    NONE = 0
    DIRECT_IO = lib.FOPEN_DIRECT_IO
    KEEP_CACHE = lib.FOPEN_KEEP_CACHE
    NONSEEKABLE = lib.FOPEN_NONSEEKABLE

class FUSE_ATTR(enum.IntEnum):
    NONE = 0
    SUBMOUNT = lib.FUSE_ATTR_SUBMOUNT

class FUSE_OPEN(enum.IntEnum):
    NONE = 0
    KILL_SUIDGID = lib.FUSE_OPEN_KILL_SUIDGID

FUSE_MIN_READ_BUFFER = lib.FUSE_MIN_READ_BUFFER

@dataclass
class FuseAttr(Struct):
    ino: int
    size: int
    blocks: int
    atime: Timespec
    mtime: Timespec
    ctime: Timespec
    mode: TypeMode
    nlink: int
    uid: int
    gid: int
    rdev: int
    blksize: int
    flags: FUSE_ATTR=FUSE_ATTR.NONE

    def _to_cffi_dict(self) -> t.Dict[str, int]:
        return {
	    "ino": self.ino,
	    "size": self.size,
	    "blocks": self.blocks,
	    "atime": self.atime.sec,
	    "mtime": self.mtime.sec,
	    "ctime": self.ctime.sec,
	    "atimensec": self.atime.nsec,
	    "mtimensec": self.mtime.nsec,
	    "ctimensec": self.ctime.nsec,
	    "mode": int(self.mode),
	    "nlink": self.nlink,
	    "uid": self.uid,
	    "gid": self.gid,
	    "rdev": self.rdev,
	    "blksize": self.blksize,
            "flags": self.flags,
        }

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_attr const*', self._to_cffi_dict())))

    T = t.TypeVar('T', bound='FuseAttr')
    @classmethod
    def from_cffi(cls: t.Type[T], struct) -> T:
        return cls(
	    ino=struct.ino,
	    size=struct.size,
	    blocks=struct.blocks,
	    atime=Timespec(sec=struct.atime, nsec=struct.atimensec),
	    mtime=Timespec(sec=struct.mtime, nsec=struct.mtimensec),
	    ctime=Timespec(sec=struct.ctime, nsec=struct.ctimensec),
	    mode=struct.mode,
	    nlink=struct.nlink,
	    uid=struct.uid,
	    gid=struct.gid,
	    rdev=struct.rdev,
	    blksize=struct.blksize,
	    flags=FUSE_ATTR(struct.flags),
        )

    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        return cls.from_cffi(ffi.cast('struct fuse_attr*', ffi.from_buffer(data)))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_attr')

@dataclass
class FuseInHeader:
    unique: int
    # nodeid 1 is the root of the filesystem; all other nodeids are returned by the FUSE server
    nodeid: int
    uid: int
    gid: int
    pid: int

    @staticmethod
    def from_cffi(struct) -> FuseInHeader:
        return FuseInHeader(
            unique=struct.unique,
            nodeid=struct.nodeid,
            uid=struct.uid,
            gid=struct.gid,
            pid=struct.pid,
        )

    @staticmethod
    def sizeof() -> int:
        return ffi.sizeof('struct fuse_in_header')

# mypy seems to not like dataclasses with abstract methods
@dataclass # type: ignore
class FuseIn(Serializable):
    hdr: FuseInHeader
    opcode: t.ClassVar[FUSE_OPCODE]

    T = t.TypeVar('T', bound='FuseIn')
    @classmethod
    @abc.abstractmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T: ...

    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_in_header*', ffi.from_buffer(data))
        if struct.len > len(data):
            raise Exception("only part of the FUSE in packet was passed to from_bytes",
                            "length field in header is", struct.len, "but passed buffer is only", len(data))
        opcode = FUSE_OPCODE(struct.opcode)
        if opcode != cls.opcode:
            raise Exception("mismatch between opcode in header", opcode, "and opcode for this class", cls.opcode)
        hdr = FuseInHeader.from_cffi(struct)
        variable = data[FuseInHeader.sizeof():struct.len]
        msg = cls.from_header(hdr, variable)
        return msg
    
    @abc.abstractmethod
    def msg_to_bytes(self) -> bytes: ...

    def to_bytes(self) -> bytes:
        msg_data = self.msg_to_bytes()
        return bytes(ffi.buffer(ffi.new('struct fuse_in_header*', {
            'len': FuseInHeader.sizeof() + len(msg_data),
            'opcode': self.opcode,
            'unique': self.hdr.unique,
            'nodeid': self.hdr.nodeid,
            'uid': self.hdr.uid,
            'gid': self.hdr.gid,
            'pid': self.hdr.pid,
        }))) + msg_data

@dataclass
class FuseInitIn(Struct):
    major: int
    minor: int
    max_readahead: int
    flags: FUSE_INIT
    opcode = FUSE_OPCODE.INIT

    T = t.TypeVar('T', bound='FuseInitIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_init_in*', ffi.from_buffer(data))
        value = cls(
            major=struct.major,
            minor=struct.minor,
            max_readahead=struct.max_readahead,
            flags=FUSE_INIT(struct.flags),
        )
        return value

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_init_in*', {
            'major': self.major,
            'minor': self.minor,
            'max_readahead': self.max_readahead,
            'flags': self.flags,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_init_in')

@dataclass
class FuseInitOp(FuseIn, Struct):
    msg: FuseInitIn
    opcode = FUSE_OPCODE.INIT

    T = t.TypeVar('T', bound='FuseInitOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseInitIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseInitIn.sizeof()

    def respond(self, msg: FuseInitOut, error: int=0) -> FuseInitResponse:
        return FuseInitResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

@dataclass
class FuseLookupOp(FuseIn):
    name: str
    opcode = FUSE_OPCODE.LOOKUP

    T = t.TypeVar('T', bound='FuseLookupOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(
            hdr=hdr,
            # strip trailing null byte
            name=data[:-1].decode(),
        )

    def msg_to_bytes(self) -> bytes:
        return self.name.encode() + b'\0'

    def respond(self, msg: FuseEntryOut, error: int=0) -> FuseLookupResponse:
        return FuseLookupResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

@dataclass
class FuseOpenIn(Struct):
    flags: O
    open_flags: FUSE_OPEN=FUSE_OPEN.NONE

    T = t.TypeVar('T', bound='FuseOpenIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_open_in*', ffi.from_buffer(data))
        return cls(flags=O(struct.flags), open_flags=FUSE_OPEN(struct.open_flags))

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_open_in*', {
            'flags': self.flags,
            'open_flags': self.open_flags,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_open_in')

@dataclass
class FuseOpenOp(FuseIn, Struct):
    msg: FuseOpenIn
    opcode = FUSE_OPCODE.OPEN

    T = t.TypeVar('T', bound='FuseOpenOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseOpenIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseOpenIn.sizeof()

    def respond(self, msg: FuseOpenOut, error: int=0) -> FuseOpenResponse:
        return FuseOpenResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

@dataclass
class FuseOpendirOp(FuseIn, Struct):
    msg: FuseOpenIn
    opcode = FUSE_OPCODE.OPENDIR

    T = t.TypeVar('T', bound='FuseOpendirOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseOpenIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseOpenIn.sizeof()

    def respond(self, msg: FuseOpenOut, error: int=0) -> FuseOpendirResponse:
        return FuseOpendirResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

class FUSE_READ(enum.IntFlag):
    NONE = 0
    LOCKOWNER = lib.FUSE_READ_LOCKOWNER

@dataclass
class FuseReadIn(Struct):
    fh: int
    offset: int
    size: int
    read_flags: FUSE_READ
    # the O flags currently set on the file; these can be changed after open with fcntl
    flags: O

    T = t.TypeVar('T', bound='FuseReadIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_read_in*', ffi.from_buffer(data))
        return cls(
            fh=struct.fh,
            offset=struct.offset,
            size=struct.size,
            read_flags=FUSE_READ(struct.read_flags),
            flags=O(struct.flags),
        )

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_read_in*', {
            'fh': self.fh,
            'offset': self.offset,
            'size': self.size,
            'read_flags': self.read_flags,
            'flags': self.flags,
            'padding': 0,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_read_in')

@dataclass
class FuseReadOp(FuseIn, Struct):
    msg: FuseReadIn
    opcode = FUSE_OPCODE.READ

    T = t.TypeVar('T', bound='FuseReadOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseReadIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseReadIn.sizeof()

    def respond(self, msg: bytes, error: int=0) -> FuseReadResponse:
        return FuseReadResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

@dataclass
class FuseReaddirOp(FuseIn, Struct):
    msg: FuseReadIn
    opcode = FUSE_OPCODE.READDIR

    T = t.TypeVar('T', bound='FuseReaddirOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseReadIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseReadIn.sizeof()

    def respond(self, msg: t.List[FuseDirent], error: int=0) -> FuseReaddirResponse:
        return FuseReaddirResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

@dataclass
class FuseReaddirplusOp(FuseIn, Struct):
    msg: FuseReadIn
    opcode = FUSE_OPCODE.READDIRPLUS

    T = t.TypeVar('T', bound='FuseReaddirplusOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseReadIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseReadIn.sizeof()

    def respond(self, msg: t.List[FuseDirentplus], error: int=0) -> FuseReaddirplusResponse:
        return FuseReaddirplusResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

@dataclass
class FuseReadlinkOp(FuseIn, Struct):
    opcode = FUSE_OPCODE.READLINK

    T = t.TypeVar('T', bound='FuseReadlinkOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr)

    def msg_to_bytes(self) -> bytes:
        return b""

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof()

    def respond(self, msg: t.Union[str, os.PathLike], error: int=0) -> FuseReadlinkResponse:
        return FuseReadlinkResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

class FUSE_GETATTR(enum.IntFlag):
    NONE = 0
    FH = lib.FUSE_GETATTR_FH

@dataclass
class FuseGetattrIn(Struct):
    getattr_flags: FUSE_GETATTR
    fh: int

    T = t.TypeVar('T', bound='FuseGetattrIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_getattr_in*', ffi.from_buffer(data))
        return cls(
            getattr_flags=FUSE_GETATTR(struct.getattr_flags),
            fh=struct.fh,
        )

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_getattr_in*', {
            'getattr_flags': self.getattr_flags,
            'dummy': 0,
            'fh': self.fh,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_getattr_in')

@dataclass
class FuseFlushIn(Struct):
    fh: int
    lock_owner: int

    T = t.TypeVar('T', bound='FuseFlushIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_flush_in*', ffi.from_buffer(data))
        return cls(fh=struct.fh, lock_owner=struct.lock_owner)

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_flush_in*', {
            'fh': self.fh,
            'unused': 0,
            'padding': 0,
            'lock_owner': self.lock_owner,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_flush_in')

@dataclass
class FuseFlushOp(FuseIn, Struct):
    msg: FuseFlushIn
    opcode = FUSE_OPCODE.FLUSH

    T = t.TypeVar('T', bound='FuseFlushOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseFlushIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseFlushIn.sizeof()

    def respond(self, error: int=0) -> FuseFlushResponse:
        return FuseFlushResponse(FuseOutHeader(error=error, unique=self.hdr.unique))

@dataclass
class FuseReleaseIn(Struct):
    fh: int
    flags: O
    release_flags: FUSE_RELEASE
    lock_owner: int

    T = t.TypeVar('T', bound='FuseReleaseIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_release_in*', ffi.from_buffer(data))
        return cls(
            fh=struct.fh,
            flags=O(struct.flags),
            release_flags=FUSE_RELEASE(struct.release_flags),
            lock_owner=struct.lock_owner,
        )

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_release_in*', {
            'fh': self.fh,
            'flags': self.flags,
            'release_flags': self.release_flags,
            'unused': 0,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_release_in')

@dataclass
class FuseReleaseOp(FuseIn, Struct):
    msg: FuseReleaseIn
    opcode = FUSE_OPCODE.RELEASE

    T = t.TypeVar('T', bound='FuseReleaseOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseReleaseIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseReleaseIn.sizeof()

    def respond(self, error: int=0) -> FuseReleaseResponse:
        return FuseReleaseResponse(FuseOutHeader(error=error, unique=self.hdr.unique))

@dataclass
class FuseReleasedirOp(FuseIn, Struct):
    msg: FuseReleaseIn
    opcode = FUSE_OPCODE.RELEASEDIR

    T = t.TypeVar('T', bound='FuseReleasedirOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseReleaseIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseReleaseIn.sizeof()

    def respond(self, error: int=0) -> FuseReleasedirResponse:
        return FuseReleasedirResponse(FuseOutHeader(error=error, unique=self.hdr.unique))

@dataclass
class FuseGetattrOp(FuseIn, Struct):
    msg: FuseGetattrIn
    opcode = FUSE_OPCODE.GETATTR

    T = t.TypeVar('T', bound='FuseGetattrOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseGetattrIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @classmethod
    def sizeof(cls) -> int:
        return FuseInHeader.sizeof() + FuseGetattrIn.sizeof()

    def respond(self, msg: FuseAttrOut, error: int=0) -> FuseGetattrResponse:
        return FuseGetattrResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=msg)

@dataclass
class FuseGetxattrIn(Serializable):
    data: str

    T = t.TypeVar('T', bound='FuseGetxattrIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_getxattr_in*', ffi.from_buffer(data))
        varsize = struct.size - 4
        variable = data[ffi.sizeof('struct fuse_getxattr_in'):]
        if len(variable) < varsize:
            raise Exception("partial fuse_getxattr_in packet, received data", len(variable), variable,
                            "expected size", struct.size)
        # -1 to strip null byte
        return cls(os.fsdecode(variable[:varsize-1]))

    def to_bytes(self) -> bytes:
        data = self.data + "\0"
        return bytes(ffi.buffer(ffi.new('struct fuse_getxattr_in*', {
            'size': len(data),
            'padding': 0,
        })))

@dataclass
class FuseGetxattrOp(FuseIn):
    # aha ok we get the name, which we have the size of.
    # that includes the null terminator
    # then we respond with the xattr data presumably
    msg: FuseGetxattrIn
    opcode = FUSE_OPCODE.GETXATTR

    T = t.TypeVar('T', bound='FuseGetxattrOp')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseInHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseGetxattrIn.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    def respond(self, data: str, error: int=0) -> FuseGetxattrResponse:
        return FuseGetxattrResponse(FuseOutHeader(error=error, unique=self.hdr.unique), msg=FuseGetxattrOut(data))

    def error(self, error: int) -> FuseErrorResponse:
        return FuseErrorResponse(FuseOutHeader(error=error, unique=self.hdr.unique))

opcode_classes: t.Dict[FUSE_OPCODE, t.Type[FuseIn]] = {
    FUSE_OPCODE.INIT: FuseInitOp,
    FUSE_OPCODE.LOOKUP: FuseLookupOp,
    FUSE_OPCODE.OPEN: FuseOpenOp,
    FUSE_OPCODE.OPENDIR: FuseOpendirOp,
    FUSE_OPCODE.READ: FuseReadOp,
    FUSE_OPCODE.READDIR: FuseReaddirOp,
    FUSE_OPCODE.READDIRPLUS: FuseReaddirplusOp,
    FUSE_OPCODE.READLINK: FuseReadlinkOp,
    FUSE_OPCODE.GETATTR: FuseGetattrOp,
    FUSE_OPCODE.GETXATTR: FuseGetxattrOp,
    FUSE_OPCODE.FLUSH: FuseFlushOp,
    FUSE_OPCODE.RELEASE: FuseReleaseOp,
    FUSE_OPCODE.RELEASEDIR: FuseReleasedirOp,
}

def fuse_in_parse_split(data: bytes) -> t.Tuple[FuseIn, bytes]:
    "Split the buffer into parsed header with variable length section, and remaining unparsed data"
    struct = ffi.cast('struct fuse_in_header*', ffi.from_buffer(data))
    if struct.len > len(data):
        raise Exception("only part of the FUSE packet was passed to _header_parse_split",
                        "length field in header is", struct.len, "but passed buffer is only", len(data))
    opcode = FUSE_OPCODE(struct.opcode)
    hdr = FuseInHeader.from_cffi(struct)
    variable = data[FuseInHeader.sizeof():struct.len]
    rest = data[struct.len:]
    # dispatch to the specific message type
    msg = opcode_classes[opcode].from_header(hdr, variable)
    return msg, rest

class FuseInList(t.List[FuseIn], Serializable):
    def to_bytes(self) -> bytes:
        ret = b""
        for ent in self:
            ret += ent.to_bytes()
        return ret

    T = t.TypeVar('T', bound='FuseInList')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        entries = []
        while data:
            # the FUSE fd will never give us a partial packet, so we don't have to rebuffer
            pkt, data = fuse_in_parse_split(data)
            entries.append(pkt)
        return cls(entries)

@dataclass
class FuseOutHeader:
    error: int
    unique: int

    @staticmethod
    def from_cffi(struct) -> FuseOutHeader:
        return FuseOutHeader(
            error=struct.error,
            unique=struct.unique,
        )

    @staticmethod
    def sizeof() -> int:
        return ffi.sizeof('struct fuse_out_header')

# mypy seems to not like dataclasses with abstract methods
@dataclass # type: ignore
class FuseOut(Serializable):
    hdr: FuseOutHeader

    T = t.TypeVar('T', bound='FuseOut')
    # @abc.abstractclassmethod
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T: ...

    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_out_header*', ffi.from_buffer(data))
        if struct.len > len(data):
            raise Exception("only part of the FUSE out packet was passed to from_bytes",
                            "length field in header is", struct.len, "but passed buffer is only", len(data))
        msg_data = data[ffi.sizeof('struct fuse_out_header'):struct.len]
        return cls.from_header(FuseOutHeader.from_cffi(struct), msg_data)
    
    @abc.abstractmethod
    def msg_to_bytes(self) -> bytes: ...

    def to_bytes(self) -> bytes:
        msg_data = self.msg_to_bytes()
        return bytes(ffi.buffer(ffi.new('struct fuse_out_header*', {
            'len': ffi.sizeof('struct fuse_out_header') + len(msg_data),
            'error': self.hdr.error,
            'unique': self.hdr.unique,
        }))) + msg_data

@dataclass
class FuseErrorResponse(FuseOut, Struct):
    T = t.TypeVar('T', bound='FuseErrorResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr)

    def msg_to_bytes(self) -> bytes:
        return b""

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof()

@dataclass
class FuseInitOut(Struct):
    major: int
    minor: int
    max_readahead: int
    flags: FUSE_INIT
    max_background: int
    congestion_threshold: int
    max_write: int
    time_gran: int

    T = t.TypeVar('T', bound='FuseInitOut')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_init_out*', ffi.from_buffer(data))
        return cls(
            major=struct.major,
            minor=struct.minor,
            max_readahead=struct.max_readahead,
            flags=FUSE_INIT(struct.flags),
            max_background=struct.max_background,
            congestion_threshold=struct.congestion_threshold,
            max_write=struct.max_write,
            time_gran=struct.time_gran,
        )

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_init_out*', {
            'major': self.major,
            'minor': self.minor,
            'max_readahead': self.max_readahead,
            'flags': self.flags,
            'max_background': self.max_background,
            'congestion_threshold': self.congestion_threshold,
            'max_write': self.max_write,
            'time_gran': self.time_gran,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_init_out')

@dataclass
class FuseInitResponse(FuseOut, Struct):
    msg: FuseInitOut

    T = t.TypeVar('T', bound='FuseInitResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseInitOut.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof() + FuseInitOut.sizeof()

@dataclass
class FuseEntryOut(Struct):
    nodeid: int
    generation: int
    entry_valid: Timespec
    attr_valid: Timespec
    attr: FuseAttr

    T = t.TypeVar('T', bound='FuseEntryOut')
    @classmethod
    def from_cffi(cls: t.Type[T], struct) -> T:
        return cls(
            nodeid=struct.nodeid,
            generation=struct.generation,
            entry_valid=Timespec(struct.entry_valid, struct.entry_valid_nsec),
            attr_valid=Timespec(struct.attr_valid, struct.attr_valid_nsec),
            attr=FuseAttr.from_cffi(struct.attr),
        )

    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        return cls.from_cffi(ffi.cast('struct fuse_entry_out*', ffi.from_buffer(data)))

    def _to_cffi_dict(self) -> t.Dict[str, t.Any]:
        return {
            'nodeid': self.nodeid,
            'generation': self.generation,
            'entry_valid': self.entry_valid.sec,
            'attr_valid': self.attr_valid.sec,
            'entry_valid_nsec': self.entry_valid.nsec,
            'attr_valid_nsec': self.attr_valid.nsec,
            'attr': self.attr._to_cffi_dict(),
        }

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_entry_out*', self._to_cffi_dict())))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_entry_out')

@dataclass
class FuseLookupResponse(FuseOut, Struct):
    msg: FuseEntryOut

    T = t.TypeVar('T', bound='FuseLookupResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseEntryOut.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof() + FuseEntryOut.sizeof()

@dataclass
class FuseOpenOut(Struct):
    fh: int
    open_flags: FOPEN

    T = t.TypeVar('T', bound='FuseOpenOut')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_open_out*', ffi.from_buffer(data))
        return cls(
            fh=struct.fh,
            open_flags=FOPEN(struct.open_flags),
        )

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_open_out*', {
            'fh': self.fh,
            'open_flags': self.open_flags,
            'padding': 0,
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_open_out')

@dataclass
class FuseOpenResponse(FuseOut, Struct):
    msg: FuseOpenOut

    T = t.TypeVar('T', bound='FuseOpenResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseOpenOut.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof() + FuseOpenOut.sizeof()

@dataclass
class FuseOpendirResponse(FuseOut, Struct):
    msg: FuseOpenOut

    T = t.TypeVar('T', bound='FuseOpendirResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseOpenOut.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof() + FuseOpenOut.sizeof()

@dataclass
class FuseReadResponse(FuseOut):
    msg: bytes

    T = t.TypeVar('T', bound='FuseReadResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=data)

    def msg_to_bytes(self) -> bytes:
        return self.msg

@dataclass
class FuseAttrOut(Struct):
    attr_valid: Timespec
    attr: FuseAttr

    T = t.TypeVar('T', bound='FuseAttrOut')
    @classmethod
    def from_header(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_attr_out*', ffi.from_buffer(data))
        return cls(
            attr_valid=Timespec(struct.attr_valid, struct.attr_valid_nsec),
            attr=FuseAttr.from_cffi(struct.attr),
        )

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct fuse_attr_out*', {
            'attr_valid': self.attr_valid.sec,
            'attr_valid_nsec': self.attr_valid.nsec,
            'dummy': 0,
            'attr': self.attr._to_cffi_dict(),
        })))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fuse_attr_out')

@dataclass
class FuseGetattrResponse(FuseOut, Struct):
    msg: FuseAttrOut

    T = t.TypeVar('T', bound='FuseGetattrResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseAttrOut.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof() + FuseAttrOut.sizeof()

@dataclass
class FuseDirent:
    ino: int
    off: int # the offset to seek to to see the next dirent
    type: DT
    name: str

    def _to_cffi_dict(self, name: bytes) -> t.Dict[str, t.Any]:
        return {
            "ino": self.ino,
            "off": self.off,
            "namelen": len(name),
            "type": self.type,
            "name": name,
        }

    @classmethod
    def from_cffi(cls, struct) -> FuseDirent:
        return cls(
            ino=struct.ino,
            off=struct.off,
            type=DT(struct.type),
            # the name is padded with null bytes to make the dirent aligned,
            # so we have to use strlen to find the end
            name=ffi.string(struct.name, struct.namelen).decode(),
        )

    def to_bytes(self) -> bytes:
        namebytes = self.name.encode() + b'\0'
        length = ffi.sizeof('struct fuse_dirent') + len(namebytes)
        padding = align(length, 8) - length
        namebytes = namebytes + bytes(padding)
        return bytes(ffi.buffer(ffi.new('struct fuse_dirent*',
                                        self._to_cffi_dict(namebytes)
        ))) + namebytes

@dataclass
class FuseReaddirResponse(FuseOut):
    msg: t.List[FuseDirent]

    T = t.TypeVar('T', bound='FuseReaddirResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        entries = []
        while len(data) > 0:
            # We do the work of from_bytes in this class instead of in Dirent because we need the
            # raw length field from the struct; merely doing len(name) will exclude padding.
            struct = ffi.cast('struct fuse_dirent*', ffi.from_buffer(data))
            record_length = ffi.sizeof('struct fuse_dirent') + struct.namelen
            if len(data) < record_length:
                raise Exception("partial packet passed to FuseDirent.from_bytes")
            entries.append(FuseDirent.from_cffi(struct))
            data = data[record_length:]
        return cls(hdr=hdr, msg=entries)

    def msg_to_bytes(self) -> bytes:
        ret = b""
        for ent in self.msg:
            ret += ent.to_bytes()
        return ret

@dataclass
class FuseDirentplus:
    entry_out: FuseEntryOut
    dirent: FuseDirent

    @classmethod
    def from_cffi(cls, struct) -> FuseDirentplus:
        return cls(
            entry_out=FuseEntryOut.from_cffi(struct.entry_out),
            dirent=FuseDirent.from_cffi(struct.dirent),
        )

    def to_bytes(self) -> bytes:
        namebytes = self.dirent.name.encode() + b'\0'
        length = ffi.sizeof('struct fuse_direntplus') + len(namebytes)
        padding = align(length, 8) - length
        namebytes = namebytes + bytes(padding)
        return bytes(ffi.buffer(ffi.new('struct fuse_direntplus*', {
            "entry_out": self.entry_out._to_cffi_dict(),
            "dirent": self.dirent._to_cffi_dict(namebytes),
        }))) + namebytes

@dataclass
class FuseReaddirplusResponse(FuseOut):
    msg: t.List[FuseDirentplus]

    T = t.TypeVar('T', bound='FuseReaddirplusResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        entries = []
        while len(data) > 0:
            # We do the work of from_bytes in this class instead of in Direntplus because we need the
            # raw length field from the struct; merely doing len(name) will exclude padding.
            struct = ffi.cast('struct fuse_direntplus*', ffi.from_buffer(data))
            record_length = ffi.sizeof('struct fuse_direntplus') + struct.namelen
            if len(data) < record_length:
                raise Exception("partial packet passed to FuseDirentplus.from_bytes")
            entries.append(FuseDirentplus.from_cffi(struct))
            data = data[record_length:]
        return cls(hdr=hdr, msg=entries)

    def msg_to_bytes(self) -> bytes:
        ret = b""
        for ent in self.msg:
            ret += ent.to_bytes()
        return ret

@dataclass
class FuseReadlinkResponse(FuseOut):
    msg: t.Union[str, os.PathLike]

    T = t.TypeVar('T', bound='FuseReadlinkResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=os.fsdecode(data))

    def msg_to_bytes(self) -> bytes:
        return os.fsencode(self.msg)

@dataclass
class FuseFlushResponse(FuseOut, Struct):
    T = t.TypeVar('T', bound='FuseFlushResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr)

    def msg_to_bytes(self) -> bytes:
        return b""

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof()

@dataclass
class FuseReleaseResponse(FuseOut, Struct):
    T = t.TypeVar('T', bound='FuseReleaseResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr)

    def msg_to_bytes(self) -> bytes:
        return b""

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof()

@dataclass
class FuseReleasedirResponse(FuseOut, Struct):
    T = t.TypeVar('T', bound='FuseReleasedirResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr)

    def msg_to_bytes(self) -> bytes:
        return b""

    @staticmethod
    def sizeof() -> int:
        return FuseOutHeader.sizeof()


@dataclass
class FuseGetxattrOut(Serializable):
    data: str

    T = t.TypeVar('T', bound='FuseGetxattrOut')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct fuse_getxattr_out*', ffi.from_buffer(data))
        variable = data[ffi.sizeof('struct fuse_getxattr_out'):]
        if len(variable) < struct.size:
            raise Exception("partial fuse_getxattr_out packet, received size", len(variable),
                            "expected size", struct.size)
        # -1 to strip null byte
        return cls(os.fsdecode(variable[:struct.size-1]))

    def to_bytes(self) -> bytes:
        data = self.data + "\0"
        return bytes(ffi.buffer(ffi.new('struct fuse_getxattr_out*', {
            'size': len(data),
            'padding': 0,
        })))

@dataclass
class FuseGetxattrResponse(FuseOut):
    msg: FuseGetxattrOut

    T = t.TypeVar('T', bound='FuseGetxattrResponse')
    @classmethod
    def from_header(cls: t.Type[T], hdr: FuseOutHeader, data: bytes) -> T:
        return cls(hdr=hdr, msg=FuseGetxattrOut.from_bytes(data))

    def msg_to_bytes(self) -> bytes:
        return self.msg.to_bytes()


#### Tests ####
from unittest import TestCase
class TestFuse(TestCase):
    def test_fuse_in_list(self) -> None:
        initial = FuseInList([
            FuseInitOp(FuseInHeader(2, 3, 4, 5, 6), FuseInitIn(7, 8, 9, FUSE_INIT.BIG_WRITES|FUSE_INIT.DONT_MASK)),
        ])
        data = initial.to_bytes()
        output = FuseInList.from_bytes(data)
        self.assertEqual(initial, output)

    def test_fuse_init_out(self) -> None:
        initial = FuseInitResponse(FuseOutHeader(error=0, unique=1),
                                   FuseInitOut(2, 3, 4, FUSE_INIT.BIG_WRITES|FUSE_INIT.DONT_MASK, 6, 7, 8, 9))
        data = initial.to_bytes()
        output = FuseInitOut.from_bytes(data)
        self.assertEqual(initial, output)
