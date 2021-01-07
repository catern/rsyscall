"`#include <fnctl.h>`"
from rsyscall._raw import lib, ffi # type: ignore
import enum
import typing as t

class AT(enum.IntFlag):
    """The flags argument to many *at syscall; mostly specifies changes to path resolution.

    Except for `AT.REMOVEDIR`, these are all path resolution changes.

    """
    NONE = 0
    FDCWD = lib.AT_FDCWD
    REMOVEDIR = lib.AT_REMOVEDIR
    "When passed to `FileDescriptor.unlinkat`, remove directories instead of linking files."
    EMPTY_PATH = lib.AT_EMPTY_PATH
    SYMLINK_NOFOLLOW = lib.AT_SYMLINK_NOFOLLOW
    SYMLINK_FOLLOW = lib.AT_SYMLINK_FOLLOW

class O(enum.IntFlag):
    "The flags argument to open and some other syscalls."
    NONE = 0
    RDONLY = lib.O_RDONLY
    WRONLY = lib.O_WRONLY
    RDWR = lib.O_RDWR
    CREAT = lib.O_CREAT
    EXCL = lib.O_EXCL
    NOCTTY = lib.O_NOCTTY
    TRUNC = lib.O_TRUNC
    APPEND = lib.O_APPEND
    NONBLOCK = lib.O_NONBLOCK
    DSYNC = lib.O_DSYNC
    DIRECT = lib.O_DIRECT
    LARGEFILE = lib.O_LARGEFILE
    DIRECTORY = lib.O_DIRECTORY
    NOFOLLOW = lib.O_NOFOLLOW
    NOATIME = lib.O_NOATIME
    CLOEXEC = lib.O_CLOEXEC
    SYNC = lib.O_SYNC
    PATH = lib.O_PATH
    TMPFILE = lib.O_TMPFILE
    # internal kernel flags, visible through FUSE and possibly other places
    FMODE_EXEC = 0x20
    FMODE_NONOTIFY = 0x4000000

class F(enum.IntEnum):
    "The cmd argument to fcntl; specifies what fcntl operation we want to do."
    SETFD = lib.F_SETFD
    GETFD = lib.F_GETFD
    SETFL = lib.F_SETFL
    ADD_SEALS = lib.F_ADD_SEALS
    GET_SEALS = lib.F_GET_SEALS

class F_SEAL(enum.IntEnum):
    "The single argument used with fcntl F.ADD_SEALS and F.GET_SEALS"
    SEAL = lib.F_SEAL_SEAL
    SHRINK = lib.F_SEAL_SHRINK
    GROW = lib.F_SEAL_GROW
    WRITE = lib.F_SEAL_WRITE
    FUTURE_WRITE = lib.F_SEAL_FUTURE_WRITE

class FD(enum.IntFlag):
    """The argument to fcntl F.SETFD and return value of fcntl F.GETFD

    This is totally different from `rsyscall.FileDescriptor`, despite
    "FD" being a frequently-used abbreviation for that class name.

    """
    CLOEXEC = lib.FD_CLOEXEC

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor

class FcntlFileDescriptor(BaseFileDescriptor):
    async def fcntl(self, cmd: F, arg: t.Optional[int]=None) -> int:
        self._validate()
        try:
            return (await _fcntl(self.task.sysif, self.near, cmd, arg))
        except OSError as exn:
            exn.filename = (self, cmd, arg)
            raise

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _fcntl(sysif: SyscallInterface, fd: near.FileDescriptor,
                 cmd: F, arg: t.Optional[t.Union[int, near.Address]]=None) -> int:
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.fcntl, fd, cmd, arg))
