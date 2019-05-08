from rsyscall._raw import lib, ffi # type: ignore
import enum

class RWF(enum.IntFlag):
    NONE = 0
    DSYNC = lib.RWF_DSYNC
    HIPRI = lib.RWF_HIPRI
    SYNC = lib.RWF_SYNC
