"`#include <sys/timerfd.h>`"
from __future__ import annotations
from rsyscall._raw import lib # type: ignore
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS
import enum
import rsyscall.near.types as near
import typing as t
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask
from rsyscall.handle.pointer import Pointer, WrittenPointer

# re-exported
from rsyscall.time import Timespec, Itimerspec

__all__ = [
    "CLOCK",
    "TFD",
    "TFD_TIMER",
    "TimerFileDescriptor",
    "Timespec",
    "Itimerspec",
]

class CLOCK(enum.IntEnum):
    REALTIME = lib.CLOCK_REALTIME
    MONOTONIC = lib.CLOCK_MONOTONIC
    BOOTTIME = lib.CLOCK_BOOTTIME
    REALTIME_ALARM = lib.CLOCK_REALTIME_ALARM
    BOOTTIME_ALARM = lib.CLOCK_BOOTTIME_ALARM

class TFD(enum.IntFlag):
    NONE = 0
    CLOEXEC = lib.EFD_CLOEXEC
    NONBLOCK = lib.EFD_NONBLOCK

class TFD_TIMER(enum.IntFlag):
    NONE = 0
    ABSTIME = lib.TFD_TIMER_ABSTIME
    CANCEL_ON_SET = lib.TFD_TIMER_CANCEL_ON_SET

async def _timerfd_create(sysif: SyscallInterface, clockid: CLOCK, flags: TFD) -> near.FileDescriptor:
    return near.FileDescriptor(await sysif.syscall(SYS.timerfd_create, clockid, flags))

async def _timerfd_settime(sysif: SyscallInterface, fd: near.FileDescriptor,
                           flags: TFD_TIMER,
                           new_value: near.Address, old_value: t.Optional[near.Address]) -> None:
    if old_value is None:
        old_value = 0 # type: ignore
    await sysif.syscall(SYS.timerfd_settime, fd, flags, new_value, old_value)

async def _timerfd_gettime(sysif: SyscallInterface, fd: near.FileDescriptor,
                           curr_value: near.Address) -> None:
    await sysif.syscall(SYS.timerfd_gettime, fd, curr_value)


T_fd = t.TypeVar('T_fd', bound='TimerFileDescriptor')
class TimerFileDescriptor(BaseFileDescriptor):
    @t.overload
    async def timerfd_settime(
            self, flags: TFD_TIMER, new_value: WrittenPointer[Itimerspec]) -> None: ...

    @t.overload
    async def timerfd_settime(
            self, flags: TFD_TIMER, new_value: WrittenPointer[Itimerspec],
            old_value: Pointer[Itimerspec]) -> Pointer[Itimerspec]: ...

    async def timerfd_settime(
            self, flags: TFD_TIMER, new_value: WrittenPointer[Itimerspec],
            old_value: t.Optional[Pointer[Itimerspec]]=None) -> t.Optional[Pointer[Itimerspec]]:
        self._validate()
        with new_value.borrow(self.task):
            if old_value:
                with old_value.borrow(self.task):
                    await _timerfd_settime(
                        self.task.sysif, self.near, flags, new_value.near, old_value.near)
                    return old_value
            else:
                await _timerfd_settime(
                    self.task.sysif, self.near, flags, new_value.near, None)
                return None

    async def timerfd_gettime(self, curr_value: Pointer[Itimerspec]) -> Pointer[Itimerspec]:
        self._validate()
        with curr_value.borrow(self.task):
            await _timerfd_gettime(self.task.sysif, self.near, curr_value.near)
            return curr_value

class TimerfdTask(FileDescriptorTask[T_fd]):
    async def timerfd_create(self, clockid: CLOCK, flags: TFD=TFD.NONE) -> T_fd:
        return self.make_fd_handle(await _timerfd_create(self.sysif, clockid, flags|TFD.CLOEXEC))
