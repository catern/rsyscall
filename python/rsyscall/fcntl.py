from rsyscall._raw import lib, ffi # type: ignore
import enum

class AT(enum.IntFlag):
    FDCWD = lib.AT_FDCWD
    REMOVEDIR = lib.AT_REMOVEDIR
    EMPTY_PATH = lib.AT_EMPTY_PATH
    SYMLINK_NOFOLLOW = lib.AT_SYMLINK_NOFOLLOW
    SYMLINK_FOLLOW = lib.AT_SYMLINK_FOLLOW
