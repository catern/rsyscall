"`#include <sys/eventfd.h>`"
from __future__ import annotations
from rsyscall._raw import lib # type: ignore
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS
import enum
import rsyscall.near.types as near
import typing as t
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask

__all__ = [
    "EFD",
    "EventFileDescriptor",
    "EventfdTask",
]

class EFD(enum.IntFlag):
    NONE = 0
    CLOEXEC = lib.EFD_CLOEXEC
    NONBLOCK = lib.EFD_NONBLOCK
    SEMAPHORE = lib.EFD_SEMAPHORE

async def _eventfd(sysif: SyscallInterface, initval: int, flags: EFD) -> near.FileDescriptor:
    "The raw, near, eventfd syscall."
    return near.FileDescriptor(await sysif.syscall(SYS.eventfd2, initval, flags))

T_fd = t.TypeVar('T_fd', bound='EventFileDescriptor')
class EventFileDescriptor(BaseFileDescriptor):
    pass

class EventfdTask(FileDescriptorTask[T_fd]):
    async def eventfd(self, initval: int, flags: EFD=EFD.NONE) -> T_fd:
        return self.make_fd_handle(await _eventfd(self.sysif, initval, flags|EFD.CLOEXEC))
