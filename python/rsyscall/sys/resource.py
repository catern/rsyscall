"`#include <sys/resource.h>`"
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct
from dataclasses import dataclass
import enum
import typing as t

__all__ = [
    "PRIO",
    "RLIMIT",
    "Rlimit",
    "ResourceTask",
]

class PRIO(enum.IntFlag):
    NONE = 0
    PROCESS = lib.PRIO_PROCESS
    PGRP = lib.PRIO_PGRP
    USER = lib.PRIO_USER

class RLIMIT(enum.IntFlag):
    NONE = 0
    AS = lib.RLIMIT_AS
    CORE = lib.RLIMIT_CORE
    CPU = lib.RLIMIT_CPU
    DATA = lib.RLIMIT_DATA
    FSIZE = lib.RLIMIT_FSIZE
    LOCKS = lib.RLIMIT_LOCKS
    MEMLOCK = lib.RLIMIT_MEMLOCK
    MSGQUEUE = lib.RLIMIT_MSGQUEUE
    NICE = lib.RLIMIT_NICE
    NOFILE = lib.RLIMIT_NOFILE
    NPROC = lib.RLIMIT_NPROC
    RSS = lib.RLIMIT_RSS
    RTPRIO = lib.RLIMIT_RTPRIO
    RTTIME = lib.RLIMIT_RTTIME
    SIGPENDING = lib.RLIMIT_SIGPENDING
    STACK = lib.RLIMIT_STACK

@dataclass
class Rlimit(Struct):
    cur: int
    max: int

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct rlimit*', (self.cur, self.max))
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='Rlimit')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct rlimit*', ffi.from_buffer(data))
        return cls(struct.rlim_cur, struct.rlim_max)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct rlimit')

#### Classes ####
import rsyscall.far
from rsyscall.handle.pointer import Pointer, WrittenPointer

class ResourceTask(rsyscall.far.Task):
    async def setpriority(self, which: PRIO, prio: int) -> None:
        """set program scheduling priority

        man: setpriority(2)
        """
        return (await _setpriority(self.sysif, which, 0, prio))

    async def getpriority(self, which: PRIO) -> int:
        return (await _getpriority(self.sysif, which, 0))

    # {get,set}rlimit have a different struct rlimit from prlimit on 32-bit architectures,
    # so we annoyingly can't use the same Rlimit type for them.
    # So we'll just implement them in terms of prlimit.
    async def setrlimit(self, resource: RLIMIT, rlim: WrittenPointer[Rlimit]) -> None:
        await self.prlimit(resource, rlim, None)

    async def getrlimit(self, resource: RLIMIT, rlim: Pointer[Rlimit]) -> Pointer[Rlimit]:
        await self.prlimit(resource, None, rlim)
        return rlim

    async def prlimit(self, resource: RLIMIT,
                      new_limit: t.Optional[Pointer[Rlimit]]=None,
                      old_limit: t.Optional[Pointer[Rlimit]]=None) -> None:
        await _prlimit(self.sysif, None, resource,
                       new_limit.near if new_limit else None,
                       old_limit.near if old_limit else None)

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS
from rsyscall.near.types import (
    Address,
    Process,
)

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

async def _prlimit(
        sysif: SyscallInterface,
        pid: t.Optional[Process],
        resource: RLIMIT,
        new_limit: t.Optional[Address]=None,
        old_limit: t.Optional[Address]=None,
) -> None:
    await sysif.syscall(SYS.prlimit64, pid or 0, resource, new_limit or 0, old_limit or 0)
