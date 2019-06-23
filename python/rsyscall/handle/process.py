from __future__ import annotations
from dataclasses import dataclass
from rsyscall.handle.pointer import Pointer
from rsyscall.linux.futex import FutexNode
from rsyscall.sched import Stack
from rsyscall.signal import SIG, Siginfo
from rsyscall.sys.wait import W, ChildState
import contextlib
import logging
import rsyscall.far
import rsyscall.near
import typing as t

logger = logging.getLogger(__name__)

@dataclass
class Process:
    """A reference to an arbitrary process on the system, not necessarily our child.

    This is essentially the equivalent of an arbitrary pid. It's not safe to signal
    arbitrary pids, because a process exit + pid wrap can cause you to signal some other
    unexpected process.

    It's only safe to signal child processes, using the ChildProcess class.  But since
    it's common to want to signal arbitrary pids even despite the danger, we provide this
    convenient class to do so.

    """
    task: rsyscall.far.Task
    near: rsyscall.near.Process

    async def kill(self, sig: SIG) -> None:
        await rsyscall.near.kill(self.task.sysif, self.near, sig)

    def _as_process_group(self) -> rsyscall.near.ProcessGroup:
        return rsyscall.near.ProcessGroup(self.near.id)

    async def killpg(self, sig: SIG) -> None:
        await rsyscall.near.kill(self.task.sysif, self._as_process_group(), sig)

    async def getpgid(self) -> rsyscall.near.ProcessGroup:
        return (await rsyscall.near.getpgid(self.task.sysif, self.near))

class ChildProcess(Process):
    """A process that is our child, which we can monitor with waitid and safely signal.

    Because a child process's pid will not be reused until we wait on its zombie, we can
    (as long as we're careful about ordering calls to waitid and kill) safely send signals
    to child processes without the possibility of signaling some other unexpected process.

    """
    def __init__(self, task: rsyscall.far.Task, near: rsyscall.near.Process, alive=True) -> None:
        self.task = task
        self.near = near
        self.death_state: t.Optional[ChildState] = None
        self.unread_siginfo: t.Optional[Pointer[Siginfo]] = None
        self.in_use = False

    def mark_dead(self, state: ChildState) -> None:
        self.death_state = state

    def did_exec(self) -> ChildProcess:
        return self

    @contextlib.contextmanager
    def borrow(self) -> t.Iterator[None]:
        if self.death_state:
            raise Exception("child process", self.near, "is no longer alive, so we can't wait on it or kill it")
        if self.unread_siginfo:
            raise Exception("for child process", self.near, "waitid or kill was call "
                            "before processing the siginfo buffer from an earlier waitid")
        if self.in_use:
            # TODO technically we could have multiple kills happening simultaneously.
            # but indeed, we can't have a kill happen while a wait is happening, nor multiple waits at a time.
            # that would be racy - we might kill the wrong process or wait on the wrong process
            raise Exception("child process", self.near, "is currently being waited on or killed,"
                            " can't use it a second time")
        self.in_use = True
        try:
            yield
        finally:
            self.in_use = False

    async def kill(self, sig: SIG) -> None:
        with self.borrow():
            await super().kill(sig)

    async def killpg(self, sig: SIG) -> None:
        # This call will throw an error if this child isn't a process group leader, but
        # it's at least guaranteed to not kill some random unrelated process group.
        with self.borrow():
            await super().killpg(sig)

    async def getpgid(self) -> rsyscall.near.ProcessGroup:
        with self.borrow():
            return await super().getpgid()

    async def setpgid(self, pgid: t.Optional[ChildProcess]) -> None:
        # the ownership model of process groups is such that the only way that
        # it's safe to use setpgid on a child process is if we're setpgid-ing to
        # the process group of another child process.
        with self.borrow():
            if pgid is None:
                await rsyscall.near.setpgid(self.task.sysif, self.near, None)
            else:
                if pgid.task.pidns != self.task.pidns:
                    raise rsyscall.far.NamespaceMismatchError(
                        "different pid namespaces", pgid.task.pidns, self.task.pidns)
                with pgid.borrow():
                    await rsyscall.near.setpgid(self.task.sysif, self.near, self._as_process_group())

    async def waitid(self, options: W, infop: Pointer[Siginfo],
                     *, rusage: t.Optional[Pointer[Siginfo]]=None) -> None:
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.borrow())
            stack.enter_context(infop.borrow(self.task))
            if rusage is not None:
                stack.enter_context(rusage.borrow(self.task))
            try:
                await rsyscall.near.waitid(self.task.sysif, self.near, infop.near, options,
                                           rusage.near if rusage else None)
            except ChildProcessError as exn:
                exn.filename = self.near
                raise
        self.unread_siginfo = infop

    def parse_waitid_siginfo(self, siginfo: Siginfo) -> t.Optional[ChildState]:
        self.unread_siginfo = None
        if siginfo.pid == 0:
            return None
        else:
            state = ChildState.make_from_siginfo(siginfo)
            if state.died():
                self.mark_dead(state)
            return state

    # helpers
    async def read_siginfo(self) -> t.Optional[ChildState]:
        if self.unread_siginfo is None:
            raise Exception("no siginfo buf to read")
        else:
            siginfo = await self.unread_siginfo.read()
            return self.parse_waitid_siginfo(siginfo)

    async def read_state_change(self) -> ChildState:
        state = await self.read_siginfo()
        if state is None:
            raise Exception("expected a state change, but siginfo buf didn't contain one")
        return state

class ThreadProcess(ChildProcess):
    """A child process with some additional stuff, just useful for resource tracking for threads.

    We need to free the resources used by our child processes when they die. This class
    makes that more straightforward.

    """
    def __init__(self, task: rsyscall.far.Task, near: rsyscall.near.Process,
                 used_stack: Pointer[Stack],
                 stack_data: Stack,
                 ctid: t.Optional[Pointer[FutexNode]],
                 tls: t.Optional[Pointer],
    ) -> None:
        super().__init__(task, near)
        self.used_stack = used_stack
        self.stack_data = stack_data
        self.ctid = ctid
        self.tls = tls

    def free_everything(self) -> None:
        # TODO don't know how to free the stack data...
        if self.used_stack.valid:
            self.used_stack.free()
        if self.ctid is not None and self.ctid.valid:
            self.ctid.free()
        if self.tls is not None and self.tls.valid:
            self.tls.free()

    def mark_dead(self, event: ChildState) -> None:
        self.free_everything()
        return super().mark_dead(event)

    def did_exec(self) -> ChildProcess:
        self.free_everything()
        return super().did_exec()
