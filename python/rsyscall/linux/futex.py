import typing as t
from rsyscall._raw import ffi, lib # type: ignore
import enum

FUTEX_WAITERS: int = lib.FUTEX_WAITERS
FUTEX_TID_MASK: int = lib.FUTEX_TID_MASK
