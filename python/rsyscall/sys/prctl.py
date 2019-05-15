from rsyscall._raw import lib # type: ignore
import enum

__all__ = [
    "PR",
    "PR_CAP_AMBIENT",
]

class PR(enum.IntEnum):
    SET_PDEATHSIG = lib.PR_SET_PDEATHSIG
    CAP_AMBIENT = lib.PR_CAP_AMBIENT

class PR_CAP_AMBIENT(enum.IntEnum):
    RAISE = lib.PR_CAP_AMBIENT_RAISE
