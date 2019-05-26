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

We also employ another trick: We use CLONE.PARENT to centralize child
monitoring. When thread A creates child thread B, we want thread B to
be able to later create children of its own, e.g. process C. Normally,
we would create a new signalfd in thread B so that it can monitor its
children. Instead, when thread B clones a new child process C, we use
CLONE.PARENT so that thread A becomes the parent of new child process
C, then we monitor process C from thread A instead of thread B. This
lowers the original creation cost of thread B (since we don't have to
make a new AsyncSignalfd, which would necessitate a new epoller - see
the docstring for AsyncSignalfd) and also improves the efficiency of
child monitoring through centralization into thread A.

"""
from __future__ import annotations
from dataclasses import dataclass
from rsyscall.concurrency import MultiplexedEvent
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.handle import WrittenPointer, Pointer, Stack, FutexNode, Task, Pointer, ChildProcess
from rsyscall.memory.ram import RAM
from rsyscall.sched import CLONE
from rsyscall.signal import SIG, Sigset, Siginfo
import trio
import contextlib
import typing as t

from rsyscall.signal import SignalBlock
from rsyscall.sys.signalfd import SFD, SignalfdSiginfo
from rsyscall.sys.wait import CLD, ChildEvent, W

class AsyncSignalfd:
    """A signalfd, registered on epoll, with a SignalBlock for the appropriate signals

    Note that signalfd and epoll have some quirks when used
    together. Specifically, a signalfd registered on an epollfd in one
    process will cause severe breakage, including deadlocks, when
    calling epoll_wait on that epollfd in another process.

    For us, this means that if we're using a signalfd for some
    process, we must also use an epoller that will be waited-on in
    that same process. We take care at call sites of
    AsyncSignalfd.make so that this is true.

    It would be very nice if this bug in signalfd was fixed, that
    would allow a single central process to monitor for signals in
    many other processes.

    """
    @classmethod
    async def make(cls, ram: RAM, task: Task, epoller: Epoller, mask: Sigset,
                   *, signal_block: SignalBlock=None,
    ) -> AsyncSignalfd:
        if task is not epoller.epoll_waiter.epfd.task:
            raise Exception("signalfd task and epoll_waiter task must be the same")
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

    def __init__(self,
                 afd: AsyncFileDescriptor,
                 signal_block: SignalBlock,
    ) -> None:
        self.afd = afd
        self.signal_block = signal_block
        self.next_signal = MultiplexedEvent(self._wait_for_some_signal)

    async def _wait_for_some_signal(self):
        # we don't care what information we get from the signal, we
        # just want to sleep until some signal happens
        await self.afd.read(await self.afd.ram.malloc(SignalfdSiginfo))
        self.next_signal = MultiplexedEvent(self._wait_for_some_signal)

class AsyncChildProcess:
    "A child process which can be monitored without blocking the thread"
    def __init__(self, process: ChildProcess, ram: RAM, sigchld_sigfd: AsyncSignalfd) -> None:
        self.process = process
        self.ram = ram
        self.sigchld_sigfd = sigchld_sigfd
        self.next_sigchld: t.Optional[MultiplexedEvent] = None

    async def waitid_nohang(self) -> t.Optional[ChildEvent]:
        if self.process.unread_siginfo is None:
            await self.process.waitid(W.EXITED|W.STOPPED|W.CONTINUED|W.ALL|W.NOHANG, await self.ram.malloc(Siginfo))
        return await self.process.read_siginfo()

    async def waitpid(self, options: W) -> ChildEvent:
        if options & W.EXITED and self.process.death_event:
            # TODO this is not really the actual behavior of waitpid...
            # if the child is already dead we'd get an ECHLD not the death event again.
            return self.process.death_event
        while True:
            # If a previous call has given us a next_sigchld to wait on, then wait we shall.
            if self.next_sigchld:
                await self.next_sigchld.wait()
            # We update next_sigchld so that the next call will to waitid will wait for
            # this event to be set before calling waitid. Note that it's important that we
            # do this update before calling waitid: If a sigchld is delivered while we're
            # calling waitid, that means our next call to waitid doesn't need to wait. If
            # we made the update after calling waitid, then we may drop that sigchld, and
            # deadlock.
            self.next_sigchld = self.sigchld_sigfd.next_signal
            event = await self.waitid_nohang()
            if event is not None:
                # we shouldn't wait the next time we're called, we should eagerly wait for
                # an event, since we don't know that one isn't there.
                self.next_sigchld = None
                if event.state(options):
                    return event
                else:
                    # TODO we shouldn't discard the event here if we're not waiting for it;
                    # unfortunately doing it right will require a lot of refactoring of waitid
                    pass

    async def check(self) -> ChildEvent:
        "Wait for this child to die, and once it does, throw if it didn't exit cleanly"
        death = await self.waitpid(W.EXITED)
        death.check()
        return death

    async def kill(self, sig: SIG=SIG.KILL) -> None:
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

@dataclass
class ChildProcessMonitor:
    """Contains all that is needed to create an AsyncChildProcess from a ChildProcess

    We also know what arguments to pass to clone so that an AsyncChildProcess may be created.

    """
    sigfd: AsyncSignalfd
    ram: RAM
    cloning_task: Task
    use_clone_parent: bool

    @staticmethod
    async def make(ram: RAM, task: Task, epoller: Epoller,
                   *, signal_block: SignalBlock=None,
    ) -> ChildProcessMonitor:
        sigfd = await AsyncSignalfd.make(ram, task, epoller, Sigset({SIG.CHLD}), signal_block=signal_block)
        return ChildProcessMonitor(sigfd, ram, task, use_clone_parent=False)

    def inherit_to_child(self, ram: RAM, child_task: Task) -> ChildProcessMonitor:
        """Create a new instance that will clone children from the passed-in task

        This requires, and checks, that the passed-in task is a child
        of the process which is used for monitoring in the current
        instance. Then the functionality is implemented by just using
        CLONE.PARENT when calling clone in child_task, and thereby
        delegating responsibility for monitoring to the parent.

        """
        if child_task.parent_task is not self.sigfd.afd.handle.task:
            raise Exception("task", child_task, "with parent_task", child_task.parent_task,
                            "is not our child; we're", self.sigfd.afd.handle.task)
        # 1. We know that child_task is a child process of self.sigfd.afd.handle.task.
        # 2. That means if we use CLONE_PARENT in child_task, the resulting processes will also be
        # child processes of self.sigfd.afd.handle.task.
        # 3. Therefore self.sigfd will be notified if and when those future child processes have some event.
        # 4. Therefore we can use self.sigfd to create AsyncChildProcesses for those future child processes.
        return ChildProcessMonitor(self.sigfd, ram, child_task, use_clone_parent=True)

    def add_child_process(self, process: ChildProcess) -> AsyncChildProcess:
        if process.task is not self.sigfd.afd.handle.task:
            raise Exception("process", process, "with parent task", process.task,
                            "is not our child; we're", self.sigfd.afd.handle.task)
        proc = AsyncChildProcess(process, self.ram, self.sigfd)
        return proc

    async def clone(self, flags: CLONE,
                    child_stack: t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[Pointer[FutexNode]]=None) -> AsyncChildProcess:
        if self.use_clone_parent:
            flags |= CLONE.PARENT
        process = await self.cloning_task.clone(flags|SIG.CHLD, child_stack, None, ctid, None)
        return self.add_child_process(process)
