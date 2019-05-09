from rsyscall._raw import ffi, lib # type: ignore
import typing as t
import enum

class MS(enum.IntFlag):
    BIND = lib.MS_BIND
    RDONLY = lib.MS_RDONLY
    REMOUNT = lib.MS_REMOUNT
