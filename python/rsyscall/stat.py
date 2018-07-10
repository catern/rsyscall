from rsyscall._raw import lib, ffi # type: ignore
import os
import typing as t
import enum

# maybe just make something compatible with os.stat_result but not the same as it?
# or just don't? make it object oriented instead?
# maybe have a mode type? for use with chmod too?
# and a timespec too for use with utimensat?
# and a uid_t and gid_t too for use with fchownat?
# and... maybe off_t too?

# and i guess the mode contains the file type as well


class ModeFileType:
    def __init__(self, check_func):
        self.check_func = check_func

    def __get__(self, instance, owner) -> bool:
        return self.check_func(instance.raw)

class Mode:
    raw: int
    # this doesn't need to be mutable
    # but maybe let's make it mutable anyway
    # file type and mode
    pass

class FileTypeMode:
    # have a separate mode GETTER to extract just the mode
    raw: int
    def get_mode(self) -> Mode:
        pass

nanoseconds_in_second = 1000*1000*1000

class StatxTimestamp:
    sec: int
    nsec: int
    def nanoseconds_since_epoch(self) -> int:
        return (self.sec*nanoseconds_in_second) + self.nsec

# maybe the syscall should just return bytes?
# then I parse it in userspace?
# getting fully realized class back?
class StatxResult:
    blksize: int
    attributes: int
    nlink: int
    uid: int
    gid: int
    ino: int
    size: int
    blocks: int
    # so each attribute has three possibilities: true, false, unsupported
    attributes_mask: int
    mode: FileTypeMode
    pass

def throw_on_error(ret: int) -> int:
    if ret < 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err))
    return ret

def statx(dirfd: int, pathname: bytes, flags: int, mask: int) -> bytes:
    pathname = ffi.new('char[]', pathname)
    statxbuf = ffi.new('struct statx*')
    throw_on_error(lib.statx(dirfd, pathname, flags, mask, statxbuf))
    return bytes(ffi.buffer(statxbuf))

def faccessat(dirfd: int, pathname: bytes, mode: int) -> None:
    pathname = ffi.new('char[]', pathname)
    throw_on_error(lib.faccessat(dirfd, pathname, mode, 0))

class DType(enum.Enum):
    BLK = lib.DT_BLK # This is a block device.
    CHR = lib.DT_CHR # This is a character device.
    DIR = lib.DT_DIR # This is a directory.
    FIFO = lib.DT_FIFO # This is a named pipe (FIFO).
    LNK = lib.DT_LNK # This is a symbolic link.
    REG = lib.DT_REG # This is a regular file.
    SOCK = lib.DT_SOCK # This is a UNIX domain socket.
    UNKNOWN = lib.DT_UNKNOWN # The file type is unknown.

class Dirent:
    inode: int
    offset: int # the offset to seek to to see the next dirent
    type: DType
    name: str

def getdents64(fd: int, count: int) -> t.List[Dirent]:
    buf = ffi.new('char[]', count)
    ret = throw_on_error(lib.getdents64(fd, buf, count))
    entries = []
    cur = ffi.cast('struct linux_dirent64*', buf)
    while True:
        entries.append(cur)
        ffi.cast('struct linux_dirent64*', buf+d_ino
    pass
