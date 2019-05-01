from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import enum

class PROT(enum.IntFlag):
    EXEC = lib.PROT_EXEC
    READ = lib.PROT_READ
    WRITE = lib.PROT_WRITE
    NONE = lib.PROT_NONE

class MAP(enum.IntFlag):
    PRIVATE = lib.MAP_PRIVATE
    SHARED = lib.MAP_SHARED
    ANONYMOUS = lib.MAP_ANONYMOUS
