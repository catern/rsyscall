"""Monitoring child processes in a non-blocking manner

The API for monitoring child processes is one of the worst-designed
parts of Unix, and Linux inherits that bad design. Still, we've tried
to provide a usable interface here.

Our basic approach is to use a signalfd waiting for SIGCHLD to learn
when an event may have happened, then call waitid until we run out of
events. This is a common way to handle it, but we have a few changes.

Contrary to the obvious implementation, we don't use
waitid(P.ALL). Instead, we make an individual waitid(P.PID) call for
each process we're currently monitoring for events.

P.ALL is unrecoverably broken and racy in many situations. It's
fundamentally the wrong API: You can't wait for only a subset of
events, you always have to handle every single event that could
happen. And worse still: When you handle the death event of a child,
that child pid is freed and can be reused; so if you use P.ALL you
must synchronize against anything that wants to operate on child pids,
to prevent pid wrap races.

P.ALL is especially bad when considering the possibility of new
children appearing. If we call clone in two threads while a third
calls waitid, and one of the created child processes dies immediately,
there is no way to prevent a race where waitid gets the death event
before the second clone completes, the pid wraps, the same pid is
returned for the second clone, and we don't know which child process
is alive and which is dead. Similar races can happen if we're pid 1 or
a subreaper and we call clone.

Issuing a batch of P.PID calls instead is much better: We can wait for
a subset of pids, and so all these worries about races go away. We
still need to synchronize between usage of the pid and calls to
waitid, but that synchronization happens for the individual child
process, not globally across all our child processes. And the
implementation becomes much simpler: Each object monitoring an
individual child process just calls waitid(P.PID) and checks the
result, instead of having to wait on some central coordinator to call
waitid(P.ALL) and send back an event.

"""
from __future__ import annotations
from dataclasses import dataclass
from rsyscall.concurrency import OneAtATime
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.handle import WrittenPointer, Pointer, Stack, FutexNode, Task, Pointer, ChildProcess
from rsyscall.memory.ram import RAM
from rsyscall.sched import CLONE
from rsyscall.signal import Signals, Sigset, Siginfo
import trio
import contextlib
import typing as t

from rsyscall.signal import SignalBlock
from rsyscall.sys.signalfd import SFD, SignalfdSiginfo
from rsyscall.sys.wait import CLD, ChildEvent, W

@dataclass(frozen=True)
class AsyncSignalfd:
    "A signalfd, registered on epoll, with a SignalBlock for the appropriate signals"
    afd: AsyncFileDescriptor
    signal_block: SignalBlock

    @classmethod
    async def make(cls, ram: RAM, task: Task, epoller: Epoller, mask: Sigset,
                   *, signal_block: SignalBlock=None,
    ) -> AsyncSignalfd:
        if signal_block is None:
            async def op(sem: RAM) -> t.Tuple[WrittenPointer[Sigset], Pointer[Sigset]]:
                return await sem.ptr(mask), await sem.malloc(Sigset)
            sigset_ptr, oldset_ptr = await ram.perform_batch(op)
            signal_block = await task.sigmask_block(sigset_ptr, oldset_ptr)
            await task.read_oldset_and_check()
        else:
            sigset_ptr = await ram.ptr(mask)
            if signal_block.mask != mask:
                raise Exception("passed-in SignalBlock", signal_block, "has mask", signal_block.mask,
                                "which does not match the mask for the AsyncSignalfd we're making", mask)
        fd = await task.signalfd(sigset_ptr, SFD.NONBLOCK)
        afd = await AsyncFileDescriptor.make_handle(epoller, ram, fd, is_nonblock=True)
        return cls(afd, signal_block)

class AsyncChildProcess:
    "A child process which can be monitored without blocking the thread"
    def __init__(self, process: ChildProcess,
                 monitor: ChildProcessMonitorInternal) -> None:
        self.process = process
        self.monitor = monitor

    async def waitid_nohang(self) -> t.Optional[ChildEvent]:
        if self.process.unread_siginfo is None:
            await self.process.waitid(W.EXITED|W.STOPPED|W.CONTINUED|W.ALL|W.NOHANG,
                                      await self.monitor.ram.malloc(Siginfo))
        return await self.process.read_siginfo()

    async def waitpid(self, options: W) -> ChildEvent:
        # TODO this is not really the actual behavior...
        if options & W.EXITED and self.process.death_event:
            return self.process.death_event
        while True:
            with self.monitor.sigchld_waiter() as waiter:
                event = await self.waitid_nohang()
                if event is None:
                    await waiter.wait_for_sigchld()
                else:
                    if event.state(options):
                        return event
                    else:
                        # TODO we shouldn't discard the event here if we're not waiting for it;
                        # but doing it right takes a lot of effort in refactoring waitid
                        pass

    async def check(self) -> ChildEvent:
        "Wait for this child to die, and once it does, throw if it didn't exit cleanly"
        death = await self.waitpid(W.EXITED)
        death.check()
        return death

    async def kill(self, sig: Signals=Signals.SIGKILL) -> None:
        "Send a signal to this child"
        if self.process.unread_siginfo:
            await self.process.read_siginfo()
        await self.process.kill(sig)

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        if self.process.death_event:
            pass
        else:
            await self.kill()
            await self.waitpid(W.EXITED)

@dataclass(eq=False)
class SigchldWaiter:
    monitor: ChildProcessMonitorInternal
    got_sigchld: bool = False

    async def wait_for_sigchld(self) -> None:
        if not self.got_sigchld:
            await self.monitor.do_wait()

class ChildProcessMonitorInternal:
    def __init__(self, ram: RAM, sigfd: AsyncSignalfd, is_reaper: bool) -> None:
        self.ram = ram
        self.sigfd = sigfd
        self.is_reaper = is_reaper
        if self.sigfd.signal_block.mask != set([Signals.SIGCHLD]):
            raise Exception("ChildProcessMonitor should get a AsyncSignalfd only for SIGCHLD")
        self.running_wait = OneAtATime()
        self.waiters: t.List[SigchldWaiter] = []

    def add_task(self, process: ChildProcess) -> AsyncChildProcess:
        proc = AsyncChildProcess(process, self)
        # self.processes.append(proc)
        return proc

    @contextlib.contextmanager
    def sigchld_waiter(self) -> t.Iterator[SigchldWaiter]:
        waiter = SigchldWaiter(self)
        self.waiters.append(waiter)
        yield waiter
        self.waiters.remove(waiter)

    async def clone(self,
                    clone_task: Task,
                    flags: CLONE,
                    child_stack: t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[Pointer]=None) -> AsyncChildProcess:
        process = await clone_task.clone(flags|Signals.SIGCHLD, child_stack, None, ctid, None)
        return self.add_task(process)

    async def do_wait(self) -> None:
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                buf = await self.ram.malloc(SignalfdSiginfo)
                # we don't care what information we get from the signal, we just want to
                # sleep until a SIGCHLD happens
                await self.sigfd.afd.read(buf)
                for waiter in self.waiters:
                    waiter.got_sigchld = True

@dataclass
class ChildProcessMonitor:
    internal: ChildProcessMonitorInternal
    cloning_task: Task
    use_clone_parent: bool
    is_reaper: bool

    @staticmethod
    async def make(ram: RAM, task: Task, epoller: Epoller,
                   *, signal_block: SignalBlock=None,
                   is_reaper: bool=False,
    ) -> ChildProcessMonitor:
        sigfd = await AsyncSignalfd.make(ram, task, epoller, Sigset({Signals.SIGCHLD}), signal_block=signal_block)
        monitor = ChildProcessMonitorInternal(ram, sigfd, is_reaper=is_reaper)
        return ChildProcessMonitor(monitor, task, use_clone_parent=False, is_reaper=is_reaper)

    def inherit_to_child(self, child_task: Task) -> ChildProcessMonitor:
        if self.is_reaper:
            # TODO we should actually look at something on the Task, I suppose, to determine if we're a reaper
            raise Exception("we're a ChildProcessMonitor for a reaper task, "
                            "we can't be inherited because we can't use CLONE_PARENT")
        if child_task.parent_task is not self.internal.sigfd.afd.handle.task:
            raise Exception("task", child_task, "with parent_task", child_task.parent_task,
                            "is not our child; we're", self.internal.sigfd.afd.handle.task)
        # we now know that the cloning task is in a process which is a child process of the waiting task.  so
        # we know that if use CLONE_PARENT while cloning in the cloning task, the resulting tasks will be
        # children of the waiting task, so we can use the waiting task to wait on them.
        return ChildProcessMonitor(self.internal, child_task, use_clone_parent=True, is_reaper=self.is_reaper)

    def inherit_to_thread(self, cloning_task: Task) -> ChildProcessMonitor:
        if self.internal.sigfd.afd.handle.task.process is not cloning_task.process:
            raise Exception("waiting task process", self.internal.sigfd.afd.handle.task.process,
                            "is not the same as cloning task process", cloning_task.process)
        # we know that the cloning task is in the same process as the waiting task. so any children the
        # cloning task starts will also be waitable-on by the waiting task.
        return ChildProcessMonitor(self.internal, cloning_task, use_clone_parent=False, is_reaper=self.is_reaper)

    async def clone(self, flags: CLONE,
                    child_stack: t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[Pointer[FutexNode]]=None) -> AsyncChildProcess:
        if self.use_clone_parent:
            flags |= CLONE.PARENT
        return (await self.internal.clone(self.cloning_task, flags, child_stack, ctid=ctid))
