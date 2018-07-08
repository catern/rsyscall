from rsyscall._raw import lib, ffi # type: ignore
import os
import typing as t

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
        return bool(instance.raw & self.bitval)

class Mode:
    raw: int
    # file type and mode
    pass

class FileTypeMode:
    # have a separate mode property to extract just the mode
    raw: int

nanoseconds_in_second = 1000*1000*1000

class StatxTimestamp:
    sec: int
    nsec: int
    def nanoseconds_since_epoch(self) -> int:
        return (self.sec*nanoseconds_since_epoch) + self.nsec

# maybe the syscall should just return bytes?
# then I parse it in userspace?
# getting fully realized class back?
class StatResult:
    blksize: int
    attributes: int
    nlink: int
    uid: int
    gid: int
    mode: int
    ino: int
    size: int
    blocks: int
    attributes_mask: int
    # so each attribute has three possibilities: true, false, unsupported


               /* The following fields are file timestamps */
               struct statx_timestamp stx_atime;  /* Last access */
               struct statx_timestamp stx_btime;  /* Creation */
               struct statx_timestamp stx_ctime;  /* Last status change */
               struct statx_timestamp stx_mtime;  /* Last modification */

               /* If this file represents a device, then the next two
                  fields contain the ID of the device */
               __u32 stx_rdev_major;  /* Major ID */
               __u32 stx_rdev_minor;  /* Minor ID */

               /* The next two fields contain the ID of the device
                  containing the filesystem where the file resides */
               __u32 stx_dev_major;   /* Major ID */
               __u32 stx_dev_minor;   /* Minor ID */
    mode: Mode
    pass

def throw_on_error(ret: int) -> None:
    if ret < 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err))

def statx(dirfd: int, pathname: bytes, flags: int, mask: int) -> StatxResult:
    pathname = ffi.new('char[]', pathname)
    statxbuf = ffi.new('struct statx*')
    throw_on_error(lib.fstatat(dirfd, pathname, statbuf, flags, mask, statxbuf))
    pass
