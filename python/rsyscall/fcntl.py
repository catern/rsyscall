"Modeled after fnctl.h."
from rsyscall._raw import lib, ffi # type: ignore
import enum

class AT(enum.IntFlag):
    "The flags argument to many *at syscall; specifies changes to path resolution."
    NONE = 0
    FDCWD = lib.AT_FDCWD
    # except this one, this one actually changes functionality
    REMOVEDIR = lib.AT_REMOVEDIR
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

FD_CLOEXEC = lib.FD_CLOEXEC
