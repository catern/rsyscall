from rsyscall._raw import lib # type: ignore
import typing as t
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

#### Classes ####
import rsyscall.far

class PrctlTask(rsyscall.far.Task):
    async def prctl(self, option: PR, arg2: int,
                    arg3: int=None, arg4: int=None, arg5: int=None) -> int:
        return (await _prctl(self.sysif, option, arg2, arg3, arg4, arg5))

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _prctl(sysif: SyscallInterface, option: PR, arg2: int,
                 arg3: t.Optional[int], arg4: t.Optional[int], arg5: t.Optional[int]) -> int:
    if arg3 is None:
        arg3 = 0
    if arg4 is None:
        arg4 = 0
    if arg5 is None:
        arg5 = 0
    return (await sysif.syscall(SYS.prctl, option, arg2, arg3, arg4, arg5))
