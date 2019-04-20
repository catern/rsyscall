from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import typing as t
import enum

class MFD(enum.IntFlag):
    CLOEXEC = lib.MFD_CLOEXEC
    
