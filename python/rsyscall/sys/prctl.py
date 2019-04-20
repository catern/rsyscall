from rsyscall._raw import lib # type: ignore
import enum

class PrctlOp(enum.IntEnum):
    SET_PDEATHSIG = lib.PR_SET_PDEATHSIG
    CAP_AMBIENT = lib.PR_CAP_AMBIENT

class CapAmbient(enum.IntEnum):
    RAISE = lib.PR_CAP_AMBIENT_RAISE
