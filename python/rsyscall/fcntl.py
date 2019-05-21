"#include <fnctl.h>"
from rsyscall._raw import lib, ffi # type: ignore
import fcntl
import enum
import os

class AT(enum.IntFlag):
    NONE = 0
    FDCWD = lib.AT_FDCWD
    REMOVEDIR = lib.AT_REMOVEDIR
    EMPTY_PATH = lib.AT_EMPTY_PATH
    SYMLINK_NOFOLLOW = lib.AT_SYMLINK_NOFOLLOW
    SYMLINK_FOLLOW = lib.AT_SYMLINK_FOLLOW

class O(enum.IntFlag):
    NONE = 0
    RDONLY = os.O_RDONLY
    WRONLY = os.O_WRONLY
    RDWR = os.O_RDWR
    CREAT = os.O_CREAT
    EXCL = os.O_EXCL
    NOCTTY = os.O_NOCTTY
    TRUNC = os.O_TRUNC
    APPEND = os.O_APPEND
    NONBLOCK = os.O_NONBLOCK
    DSYNC = os.O_DSYNC
    DIRECT = os.O_DIRECT
    LARGEFILE = os.O_LARGEFILE
    DIRECTORY = os.O_DIRECTORY
    NOFOLLOW = os.O_NOFOLLOW
    NOATIME = os.O_NOATIME
    CLOEXEC = os.O_CLOEXEC
    SYNC = os.O_SYNC
    PATH = os.O_PATH
    TMPFILE = os.O_TMPFILE

class F(enum.IntEnum):
    SETFD = fcntl.F_SETFD
    GETFD = fcntl.F_GETFD
    SETFL = fcntl.F_SETFL

FD_CLOEXEC = fcntl.FD_CLOEXEC
