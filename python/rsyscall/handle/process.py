from __future__ import annotations
from rsyscall._raw import ffi # type: ignore
from dataclasses import dataclass
from rsyscall.command import Command
from rsyscall.handle.pointer import Pointer, WrittenPointer
from rsyscall.linux.futex import FutexNode
from rsyscall.sched import Stack, CLONE, _clone, _unshare
from rsyscall.signal import SIG, Siginfo, _kill
from rsyscall.sys.resource import PRIO, _setpriority, _getpriority
from rsyscall.sys.wait import W, ChildState, _waitid
from rsyscall.unistd.credentials import _getpgid, _setpgid
import contextlib
import logging
import rsyscall.far
import rsyscall.near
import typing as t

logger = logging.getLogger(__name__)

@dataclass
class Pid:
    """A reference to an arbitrary process on the system, not necessarily our child.

    This is essentially the equivalent of an arbitrary pid. It's not safe to signal
    arbitrary pids, because a process exit + pid wrap can cause you to signal some other
    unexpected process.

    It's only safe to signal child processes, using the ChildPid class.  But since
    it's common to want to signal arbitrary pids even despite the danger, we provide this
    convenient class to do so.

    """
    task: rsyscall.far.Task
    near: rsyscall.near.Pid

    async def kill(self, sig: SIG) -> None:
        await _kill(self.task.sysif, self.near, sig)

    def _as_process_group(self) -> rsyscall.near.Pgid:
        return rsyscall.near.Pgid(self.near.id)

    async def killpg(self, sig: SIG) -> None:
        await _kill(self.task.sysif, self._as_process_group(), sig)

    async def getpgid(self) -> rsyscall.near.Pgid:
        return (await _getpgid(self.task.sysif, self.near))

    async def setpriority(self, prio: int) -> None:
        return (await _setpriority(self.task.sysif, PRIO.PROCESS, self.near.id, prio))

    async def getpriority(self) -> int:
        return (await _getpriority(self.task.sysif, PRIO.PROCESS, self.near.id))

    def __repr__(self) -> str:
        name = type(self).__name__
        return f"{name}({self.near}, parent={self.task})"

class ChildPid(Pid):
    """A process that is our child, which we can monitor with waitid and safely signal.

    Because a child process's pid will not be reused until we wait on its zombie, we can
    (as long as we're careful about ordering calls to waitid and kill) safely send signals
    to child processes without the possibility of signaling some other unexpected process.

    """
    def __init__(self, task: rsyscall.far.Task, near: rsyscall.near.Pid, alive=True) -> None:
        self.task = task
        self.near = near
        self.death_state: t.Optional[ChildState] = None
        self.unread_siginfo: t.Optional[Pointer[Siginfo]] = None
        self.in_use = False
        # the command this process exec'd; primarily useful for debugging, but we justify
        # its presence by thinking that the Command might hold references to resources
        # that the process is now using, like temporary directory paths.
        self.command: t.Optional[Command] = None

    def mark_dead(self, state: ChildState) -> None:
        self.death_state = state

    def did_exec(self, command: t.Optional[Command]) -> ChildPid:
        self.command = command
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

    async def getpgid(self) -> rsyscall.near.Pgid:
        with self.borrow():
            return await super().getpgid()

    async def setpgid(self, pgid: t.Optional[ChildPid]) -> None:
        # the ownership model of process groups is such that the only way that
        # it's safe to use setpgid on a child process is if we're setpgid-ing to
        # the process group of another child process.
        with self.borrow():
            if pgid is None:
                await _setpgid(self.task.sysif, self.near, None)
            else:
                if pgid.task.pidns != self.task.pidns:
                    raise rsyscall.far.NamespaceMismatchError(
                        "different pid namespaces", pgid.task.pidns, self.task.pidns)
                with pgid.borrow():
                    await _setpgid(self.task.sysif, self.near, self._as_process_group())

    async def waitid(self, options: W, infop: Pointer[Siginfo],
                     *, rusage: t.Optional[Pointer[Siginfo]]=None) -> None:
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.borrow())
            stack.enter_context(infop.borrow(self.task))
            if rusage is not None:
                stack.enter_context(rusage.borrow(self.task))
            try:
                await _waitid(self.task.sysif, self.near, infop.near, options,
                              rusage.near if rusage else None)
            except ChildProcessError as exn:
                exn.filename = self.near
                raise
        self.unread_siginfo = infop

    def parse_waitid_siginfo(self, siginfo: Siginfo) -> t.Optional[ChildState]:
        self.unread_siginfo = None
        # this is to catch the case where we did waitid(W.NOHANG) and there was no event
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

class ProcessPid(ChildPid):
    """A child process with some additional stuff, just useful for resource tracking for `rsyscall.thread`s.

    We need to free the resources used by our child processes when they die. This class
    makes that more straightforward.

    """
    def __init__(self, task: rsyscall.far.Task, near: rsyscall.near.Pid,
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

    def did_exec(self, command: t.Optional[Command]) -> ChildPid:
        self.free_everything()
        return super().did_exec(command)

    def __repr__(self) -> str:
        name = type(self).__name__
        if self.command or self.death_state:
            # pretend to be a ChildPid if we've exec'd or died
            name = 'ChildPid'
        return f"{name}({self.near}, parent={self.task})"

from rsyscall.memory.allocation_interface import AllocatorInterface

class PidTask(rsyscall.far.Task):
    def __init__(self,
                 sysif: rsyscall.near.SyscallInterface,
                 pid: t.Union[rsyscall.near.Pid, Pid],
                 fd_table: rsyscall.far.FDTable,
                 address_space: rsyscall.far.AddressSpace,
                 allocator: AllocatorInterface,
                 pidns: rsyscall.far.PidNamespace,
                 mountns: rsyscall.far.MountNamespace,
    ) -> None:
        if isinstance(pid, Pid):
            near_pid = pid.near
            self.pid = pid
            self.parent_task: t.Optional[rsyscall.far.Task] = pid.task
        else:
            near_pid = pid
            self.pid = Pid(self, pid)
            self.parent_task = None
        super().__init__(sysif, near_pid, fd_table, address_space, allocator, pidns, mountns)

    async def clone(self, flags: CLONE,
                    # these two pointers must be adjacent; the end of the first is the start of the
                    # second. the first is the allocation for stack growth, the second is the data
                    # we've written on the stack that will be popped off for arguments.
                    child_stack: t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                    ptid: t.Optional[Pointer],
                    ctid: t.Optional[Pointer[FutexNode]],
                    # this points to anything, it depends on the process implementation
                    newtls: t.Optional[Pointer]) -> ProcessPid:
        clone_parent = bool(flags & CLONE.PARENT)
        if clone_parent:
            if self.parent_task is None:
                raise Exception("using CLONE.PARENT, but we don't know our parent task")
            # TODO also check that the parent_task hasn't shut down... not sure how to do that
            owning_task = self.parent_task
        else:
            owning_task = self
        with contextlib.ExitStack() as stack:
            stack_alloc, stack_data = child_stack
            if (int(stack_data.near) % 16) != 0:
                raise Exception("child stack must have 16-byte alignment, so says Intel")
            stack_alloc_end = stack_alloc.near + stack_alloc.size()
            if stack_alloc_end != stack_data.near:
                raise Exception("the end of the stack allocation pointer", stack_alloc_end,
                                "and the beginning of the stack data pointer", stack_data.near,
                                "must be the same")
            stack.enter_context(stack_alloc.borrow(self))
            stack.enter_context(stack_data.borrow(self))
            ptid_n = self._borrow_optional(stack, ptid)
            ctid_n = self._borrow_optional(stack, ctid)
            newtls_n = self._borrow_optional(stack, newtls)
            pid = await _clone(self.sysif, flags, stack_data.near, ptid_n,
                                                ctid_n + ffi.offsetof('struct futex_node', 'futex') if ctid_n else None,
                                                newtls_n)
        # TODO the safety of this depends on no-one borrowing/freeing the stack in borrow __aexit__
        # should try to do this a bit more robustly...
        merged_stack = stack_alloc.merge(stack_data)
        return ProcessPid(owning_task, pid, merged_stack, stack_data.value, ctid, newtls)

    def _make_pid(self, pid: int) -> Pid:
        return Pid(self, rsyscall.near.Pid(pid))
