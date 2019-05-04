from __future__ import annotations
import typing as t
from dataclasses import dataclass
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.signal import Siginfo, Signals
import enum

class IdType(enum.IntEnum):
    PID = lib.P_PID # Wait for the child whose process ID matches id.
    PGID = lib.P_PGID # Wait for any child whose process group ID matches id.
    ALL = lib.P_ALL # Wait for any child; id is ignored.

class CLD(enum.IntEnum):
    EXITED = lib.CLD_EXITED # child called _exit(2)
    KILLED = lib.CLD_KILLED # child killed by signal
    DUMPED = lib.CLD_DUMPED # child killed by signal, and dumped core
    STOPPED = lib.CLD_STOPPED # child stopped by signal
    TRAPPED = lib.CLD_TRAPPED # traced child has trapped
    CONTINUED = lib.CLD_CONTINUED # child continued by SIGCONT

class W(enum.IntFlag):
    # wait for different statuses
    EXITED = lib.WEXITED
    STOPPED = lib.WSTOPPED
    CONTINUED = lib.WCONTINUED
    # additional options
    NOHANG = lib.WNOHANG
    NOWAIT = lib.WNOWAIT
    # wait for different kinds of children
    CLONE = lib._WCLONE
    ALL = lib._WALL
    NOTHREAD = lib._WNOTHREAD

class UncleanExit(Exception):
    pass

@dataclass
class ChildEvent:
    code: CLD
    pid: int
    uid: int
    exit_status: t.Optional[int]
    sig: t.Optional[Signals]

    @staticmethod
    def make(code: CLD, pid: int, uid: int, status: int) -> ChildEvent:
        if code is CLD.EXITED:
            return ChildEvent(code, pid, uid, status, None)
        else:
            return ChildEvent(code, pid, uid, None, Signals(status))

    @staticmethod
    def make_from_siginfo(siginfo: Siginfo) -> ChildEvent:
        return ChildEvent.make(CLD(siginfo.code),
                               pid=siginfo.pid, uid=siginfo.uid,
                               status=siginfo.status)

    def died(self) -> bool:
        return self.code in [CLD.EXITED, CLD.KILLED, CLD.DUMPED]
    def clean(self) -> bool:
        return self.code == CLD.EXITED and self.exit_status == 0

    def check(self) -> None:
        if self.clean():
            return None
        else:
            raise UncleanExit(self)

    def killed_with(self) -> Signals:
        """What signal was the child killed with?

        Throws if the child was not killed with a signal.

        """
        if not self.died():
            raise Exception("Child isn't dead")
        if self.sig is None:
            raise Exception("Child wasn't killed with a signal")
        return self.sig


#### Tests ####
from unittest import TestCase

class TestWait(TestCase):
    def test_child_event(self) -> None:
        event = ChildEvent.make_from_siginfo(Siginfo(code=CLD.EXITED, pid=1, uid=13, status=1))
        self.assertFalse(event.clean())
