from rsyscall._raw import ffi, lib # type: ignore
import typing as t
import enum

class MS(enum.IntFlag):
    BIND = lib.MS_BIND
