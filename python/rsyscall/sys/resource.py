from rsyscall._raw import lib # type: ignore
import enum
import typing as t

__all__ = ["PRIO"]

class PRIO(enum.IntFlag):
    NONE = 0
    PROCESS = lib.PRIO_PROCESS
    PGRP = lib.PRIO_PGRP
    USER = lib.PRIO_USER

#### Classes ####
import rsyscall.far

class ResourceTask(rsyscall.far.Task):
    async def setpriority(self, which: PRIO, prio: int) -> None:
        return (await _setpriority(self.sysif, which, 0, prio))

    async def getpriority(self, which: PRIO) -> int:
        return (await _getpriority(self.sysif, which, 0))

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _setpriority(
        sysif: SyscallInterface,
        which: PRIO,
        who: int,
        prio: int,
) -> None:
    """The raw setpriority syscall

    This syscall is tricky to assign a type to. It's similar to waitid, but has the extra
    complication that we can pass 0 for the "who" argument to operate on the current process/process
    group/user, as determined by PRIO.

    I considered making the type of "who", t.Union[Process, ProcessGroup, User, PRIO], and removing
    the "which" argument; passing PRIO would cause setpriority to operate on the current
    Process/ProcessGroup/User as determined by the PRIO value. That's the same as how our waitid
    wrapper works, but that usage of PRIO seemed too weird.

    """
    await sysif.syscall(SYS.setpriority, which, who, prio)

async def _getpriority(
        sysif: SyscallInterface,
        which: PRIO,
        who: int,
) -> int:
    return await sysif.syscall(SYS.getpriority, which, who)
