"""Monitoring child processes in a non-blocking manner

The API for monitoring child processes is one of the worst-designed parts of
Unix, and Linux inherits that bad design. Still, we've tried to provide a usable
interface here.

Our basic approach is to use a signalfd waiting for SIGCHLD to learn when a
state change may have happened, then call waitid until we run out of state
changes. This is a common way to handle it, but we have a few changes.

Contrary to the obvious implementation, we don't use waitid(P.ALL).  Instead, we
make an individual waitid(P.PID) call for each process we're currently
monitoring for state changes.

P.ALL is unrecoverably broken and racy in many situations. It's fundamentally
the wrong API: You can't wait for only a subset of processes, you always have to
handle every single state change that could happen for any process. And worse:
When you handle the death state change for a child, that child pid is freed and
can be reused; so you must synchronize against anything that wants to operate on
child pids, to prevent pid wrap races.

P.ALL is especially bad when considering the possibility of new children
appearing.  If we call clone in two threads while a third calls waitid, and one
of the created child processes dies immediately, there is no way to prevent a
race where waitid gets the death state change before the second clone completes,
the pid wraps, the same pid is returned for the second clone, and we don't know
which child process is alive and which is dead. Similar races can happen if
we're pid 1 or a subreaper and we call clone.

Issuing a batch of P.PID calls instead is much better: We can wait for a subset
of pids, and so all these worries about races go away.  We still need to
synchronize between usage of the pid and calls to waitid, but that
synchronization happens for the individual child process, not globally across
all our child processes. And the implementation becomes much simpler: Each
object monitoring an individual child process just calls waitid(P.PID) and
checks the result, instead of having to wait on some central coordinator to call
waitid(P.ALL) and send back the state changes.

We also employ another trick: We use CLONE.PARENT to centralize child
monitoring.  When thread A creates child thread B, we want thread B to be able
to later create children of its own, e.g. process C.  Normally, we would create
a new signalfd in thread B so that it can monitor its children. Instead, when
thread B clones a new child process C, we use CLONE.PARENT so that thread A
becomes the parent of new child process C, then we monitor process C from thread
A instead of thread B.  This lowers the original creation cost of thread B
(since we don't have to make a new AsyncSignalfd, which would necessitate a new
epoller - see the docstring for AsyncSignalfd) and also improves the efficiency
of child monitoring through centralization into thread A.

"""
from __future__ import annotations
from dataclasses import dataclass
from dneio import RequestQueue, reset, Event
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.handle import WrittenPointer, Pointer, Stack, FutexNode, Task, Pointer, ChildProcess
from rsyscall.memory.ram import RAM
from rsyscall.near.sysif import SyscallError
from rsyscall.sched import CLONE
from rsyscall.signal import SIG, Sigset, Siginfo
import trio
import contextlib
import typing as t
import logging
logger = logging.getLogger(__name__)

from rsyscall.signal import SignalBlock
from rsyscall.sys.signalfd import SFD, SignalfdSiginfo
from rsyscall.sys.wait import CLD, ChildState, W, CalledProcessError

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
        """Make a signalfd and register it on the epoller, possibly blocking signals

        If the signals are already blocked, the user can pass in a SignalBlock to
        represent that, and save the need to make the SignalBlock.

        """
        if task is not epoller.epoll_waiter.epfd.task:
            raise Exception("signalfd task and epoll_waiter task must be the same")
        if signal_block is None:
            async def op(sem: RAM) -> t.Tuple[WrittenPointer[Sigset], Pointer[Sigset]]:
                return await sem.ptr(mask), await sem.malloc(Sigset)
            sigset_ptr, oldset_ptr = await ram.perform_batch(op)
            signal_block = await task.sigmask_block(sigset_ptr, oldset_ptr)
            await task.read_oldset_and_check()
        else:
            sigset_ptr = signal_block.newset
        afd = await AsyncFileDescriptor.make(epoller, ram, await task.signalfd(sigset_ptr, SFD.NONBLOCK))
        return cls(afd, signal_block, await ram.malloc(SignalfdSiginfo))

    def __init__(self,
                 afd: AsyncFileDescriptor,
                 signal_block: SignalBlock,
                 buf: Pointer[SignalfdSiginfo],
    ) -> None:
        "Use the constructor method AsyncSignalfd.make"
        self.afd = afd
        self.signal_block = signal_block
        self.buf = buf
        self.next_signal = Event()
        reset(self._run())

    async def _run(self) -> None:
        while True:
            try:
                valid, rest = await self.afd.read(self.buf)
            except SyscallError as syscall_error:
                final_exn = syscall_error
                break
            ev, self.next_signal = self.next_signal, Event()
            # we discard the signal information...
            ev.set()
            self.buf = valid + rest
        self.next_signal.close(final_exn)

class AsyncChildProcess:
    "A child process which can be monitored without blocking the thread"
    def __init__(self, process: ChildProcess, ram: RAM, sigchld_sigfd: AsyncSignalfd) -> None:
        self.process = process
        self.ram = ram
        self.sigchld_sigfd = sigchld_sigfd
        self.next_sigchld: t.Optional[Event] = None

    def __repr__(self) -> str:
        name = type(self).__name__
        return f'{name}({self.process})'

    async def _waitid_nohang(self) -> t.Optional[ChildState]:
        if self.process.unread_siginfo:
            # if we performed a waitid before, and it contains an event, we don't need to
            # waitid again.
            result = await self.process.read_siginfo()
            # but if there's no event in this previous waitid, we need to waitid now; if
            # we don't, we might erroneously block waiting for a SIGCHLD that happened
            # between the previous waitid and now, and was consumed at that time.
            if result:
                return result
        siginfo_buf = await self.ram.malloc(Siginfo)
        await self.process.waitid(W.EXITED|W.STOPPED|W.CONTINUED|W.NOHANG, siginfo_buf)
        return await self.process.read_siginfo()

    async def waitpid(self, options: W) -> ChildState:
        "Wait for a child state change in this child, like waitid(P.PID)"
        if options & W.EXITED and self.process.death_state:
            # TODO this is not really the actual behavior of waitpid...
            # if the child is already dead we'd get an ECHLD not the death state change again.
            return self.process.death_state
        while True:
            # If a previous call has given us a next_sigchld to wait on, then wait we shall.
            if self.next_sigchld:
                await self.next_sigchld.wait()
                # we shouldn't wait for SIGCHLD the next time we're called, we should eagerly call
                # waitid, since there may still be state changes to fetch.
                self.next_sigchld = None
            # We have to save this signal event before calling waitid, otherwise we may deadlock: If
            # a SIGCHLD is delivered while we're calling waitid, then saved_sigchld will be
            # different from self.sigchld_sigfd.next_signal after the waitid; and if we use the
            # value of self.sigchld_sigfd.next_signal after the waitid, we'll be waiting for a
            # SIGCHLD that will never come.
            saved_sigchld = self.sigchld_sigfd.next_signal
            state_change = await self._waitid_nohang()
            if state_change is not None:
                if state_change.state(options):
                    return state_change
                else:
                    # TODO we shouldn't discard the state change here if we're not waiting for it;
                    # unfortunately doing it right will require a lot of refactoring of waitid
                    pass
            else:
                # we know for sure that there will only be state changes fetchable by waitid after
                # waiting for this SIGCHLD event. note that this event may have already happened, if
                # we received a SIGCHLD while calling waitid.
                self.next_sigchld = saved_sigchld

    async def wait(self, options: W=W.EXITED|W.STOPPED|W.CONTINUED) -> ChildState:
        return await self.waitpid(options)

    async def check(self) -> ChildState:
        "Wait for this child to die, and once it does, throw `rsyscall.sys.wait.CalledProcessError` if it didn't exit cleanly"
        try:
            death = await self.waitpid(W.EXITED)
        except trio.Cancelled:
            await self.kill(SIG.TERM)
            raise
        if not death.clean():
            if self.process.command:
                raise CalledProcessError(death, self.process.command)
            else:
                raise CalledProcessError(death)
            pass
        return death

    async def kill(self, sig: SIG=SIG.KILL) -> None:
        "Send a signal to this child"
        if self.process.unread_siginfo:
            await self.process.read_siginfo()
        await self.process.kill(sig)

    async def killpg(self, sig: SIG=SIG.KILL) -> None:
        "Send a signal to the process group corresponding to this child"
        if self.process.unread_siginfo:
            await self.process.read_siginfo()
        await self.process.killpg(sig)

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        if self.process.death_state:
            pass
        else:
            await self.kill()
            await self.waitpid(W.EXITED)

@dataclass
class ChildProcessMonitor:
    """Contains all that is needed to create an AsyncChildProcess from a ChildProcess

    We also know what arguments to pass to clone so that an AsyncChildProcess may be created.

    Use ChildProcessMonitor.make to create.

    """
    sigfd: AsyncSignalfd
    ram: RAM
    cloning_task: Task
    use_clone_parent: bool

    @staticmethod
    async def make(ram: RAM, task: Task, epoller: Epoller,
                   *, signal_block: SignalBlock=None,
    ) -> ChildProcessMonitor:
        """Make a ChildProcessMonitor, possibly blocking signals

        If the signals are already blocked, the user can pass in a SignalBlock to
        represent that, and save the need to make the SignalBlock.

        """
        sigfd = await AsyncSignalfd.make(ram, task, epoller, Sigset({SIG.CHLD}), signal_block=signal_block)
        return ChildProcessMonitor(sigfd, ram, task, use_clone_parent=False)

    def inherit_to_child(self, child_task: Task) -> ChildProcessMonitor:
        """Create a new instance that will clone children from the passed-in task

        This requires, and checks, that the passed-in task is a child of the process which
        is used for monitoring in the current instance. Then the functionality is
        implemented by just using CLONE.PARENT when calling clone in child_task, and
        thereby delegating responsibility for monitoring to the parent.

        """
        if child_task.parent_task is not self.sigfd.afd.handle.task:
            raise Exception("task", child_task, "with parent_task", child_task.parent_task,
                            "is not our child; we're", self.sigfd.afd.handle.task)
        # 1. We know that child_task is a child process of self.sigfd.afd.handle.task.
        # 2. That means if we use CLONE_PARENT in child_task, the resulting processes will also be
        # child processes of self.sigfd.afd.handle.task.
        # 3. Therefore self.sigfd will be notified if and when those future child processes have some state change.
        # 4. Therefore we can use self.sigfd to create AsyncChildProcesses for those future child processes.
        return ChildProcessMonitor(self.sigfd, self.ram, child_task, use_clone_parent=True)

    def add_child_process(self, process: ChildProcess) -> AsyncChildProcess:
        """Create an AsyncChildProcess which monitors the passed-in ChildProcess.

        We check that the passed-in process is in fact a child of the task associated with
        this ChildProcessMonitor before returning the AsyncChildProcess; otherwise the
        AsyncChildProcess wouldn't be woken up at the correct times to read child status
        changes.

        """
        if process.task is not self.sigfd.afd.handle.task:
            raise Exception("process", process, "with parent task", process.task,
                            "is not our child; we're", self.sigfd.afd.handle.task)
        proc = AsyncChildProcess(process, self.ram, self.sigfd)
        return proc

    async def clone(self, flags: CLONE,
                    child_stack: t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[Pointer[FutexNode]]=None) -> AsyncChildProcess:
        """Call `clone` with these arguments and return an AsyncChildProcess monitoring the resulting child

        We'll use CLONE.PARENT if necessary to create a ChildProcess that is monitorable
        by this ChildProcessMonitor.

        """
        if self.use_clone_parent:
            flags |= CLONE.PARENT
        process = await self.cloning_task.clone(flags|SIG.CHLD, child_stack, None, ctid, None)
        return self.add_child_process(process)
