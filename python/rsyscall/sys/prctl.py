"`#include <sys/prctl.h>`"
from rsyscall._raw import lib # type: ignore
import typing as t
import enum

__all__ = [
    "PR",
    "PR_CAP_AMBIENT",
    "PrctlTask",
]

class PR(enum.IntEnum):
    SET_PDEATHSIG = lib.PR_SET_PDEATHSIG
    CAP_AMBIENT = lib.PR_CAP_AMBIENT

class PR_CAP_AMBIENT(enum.IntEnum):
    RAISE = lib.PR_CAP_AMBIENT_RAISE

#### Classes ####
import rsyscall.far
from rsyscall.sys.capability import CAP
from rsyscall.signal import SIG

class PrctlTask(rsyscall.far.Task):
    "A base class providing the `prctl` syscall"

    async def prctl_set_pdeathsig(self, option: t.Literal[PR.SET_PDEATHSIG], arg2: t.Union[SIG, t.Literal[0]]) -> None:
        await _prctl(self.sysif, option, arg2)

    async def prctl_cap_ambient(self, option: t.Literal[PR.CAP_AMBIENT], arg2: PR_CAP_AMBIENT, arg3: CAP) -> int:
        return await _prctl(self.sysif, option, arg2, arg3)

    @t.overload
    async def prctl(self, option: t.Literal[PR.SET_PDEATHSIG], arg2: t.Union[SIG, t.Literal[0]]) -> None: ...
    @t.overload
    async def prctl(self, option: t.Literal[PR.CAP_AMBIENT], arg2: PR_CAP_AMBIENT, arg3: CAP) -> int: ...

    async def prctl(self, option: PR, arg2, arg3=0, arg4=0, arg5=0) -> t.Union[int, None]:
        """operations on a process or thread

        This has overloads for each prctl option, so it's type-safe to use this method.

        man: prctl(2)
        """
        if option is PR.SET_PDEATHSIG:
            return await self.prctl_set_pdeathsig(option, arg2)
        elif option is PR.CAP_AMBIENT:
            return await self.prctl_cap_ambient(option, arg2, arg3)
        else:
            return await _prctl(self.sysif, option, arg2, arg3, arg4, arg5)

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _prctl(sysif: SyscallInterface, option: PR, arg2: t.Union[int, near.Address],
                 arg3: t.Optional[t.Union[int, near.Address]]=None, arg4: t.Optional[t.Union[int, near.Address]]=None,
                 arg5: t.Optional[t.Union[int, near.Address]]=None) -> int:
    if arg3 is None:
        arg3 = 0
    if arg4 is None:
        arg4 = 0
    if arg5 is None:
        arg5 = 0
    return (await sysif.syscall(SYS.prctl, option, arg2, arg3, arg4, arg5))
