from __future__ import annotations
import rsyscall.handle as handle
from rsyscall.handle import WrittenPointer, Pointer, Stack, FutexNode
from rsyscall.sys.signalfd import SFD, SignalfdSiginfo
from rsyscall.signal import Signals, Sigset, Siginfo
import contextlib
from rsyscall.signal import SignalBlock
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor
from rsyscall.concurrency import OneAtATime
from rsyscall.sched import CLONE
from rsyscall.memory.ram import RAM
from rsyscall.sys.wait import CLD, ChildEvent, W
from rsyscall.batch import BatchSemantics
from dataclasses import dataclass
import typing as t

class SignalQueue:
    def __init__(self, signal_block: SignalBlock, sigfd: AsyncFileDescriptor) -> None:
        self.signal_block = signal_block
        self.sigfd = sigfd

    @classmethod
    async def make(cls, ram: RAM, task: handle.Task, epoller: EpollCenter, mask: Sigset,
                   *, signal_block: SignalBlock=None,
    ) -> SignalQueue:
        if signal_block is None:
            def op(sem: BatchSemantics) -> t.Tuple[WrittenPointer[Sigset], Pointer[Sigset]]:
                return sem.to_pointer(mask), sem.malloc_struct(Sigset)
            sigset_ptr, oldset_ptr = await ram.perform_batch(op)
            signal_block = await task.sigmask_block(sigset_ptr, oldset_ptr)
            await task.read_oldset_and_check()
        else:
            sigset_ptr = await ram.to_pointer(mask)
            if signal_block.mask != mask:
                raise Exception("passed-in SignalBlock", signal_block, "has mask", signal_block.mask,
                                "which does not match the mask for the SignalQueue we're making", mask)
        sigfd = await task.signalfd(sigset_ptr, SFD.NONBLOCK|SFD.CLOEXEC)
        async_sigfd = await AsyncFileDescriptor.make_handle(epoller, ram, sigfd, is_nonblock=True)
        return cls(signal_block, async_sigfd)

    async def read(self, buf: handle.Pointer) -> handle.Pointer:
        validp, _ = await self.sigfd.read_handle(buf)
        return validp

class AsyncChildProcess:
    def __init__(self, process: handle.ChildProcess,
                 monitor: ChildProcessMonitorInternal) -> None:
        self.process = process
        self.monitor = monitor

    async def waitid_nohang(self) -> t.Optional[ChildEvent]:
        if self.process.unread_siginfo is None:
            await self.process.waitid(W.EXITED|W.STOPPED|W.CONTINUED|W.ALL|W.NOHANG,
                                      await self.monitor.ram.malloc_struct(Siginfo))
        return await self.process.read_siginfo()

    async def wait(self) -> t.List[ChildEvent]:
        with self.monitor.sigchld_waiter() as waiter:
            while True:
                event = await self.waitid_nohang()
                if event is None:
                    await waiter.wait_for_sigchld()
                else:
                    return [event]

    async def wait_for_exit(self) -> ChildEvent:
        if self.process.death_event:
            return self.process.death_event
        while True:
            for event in (await self.wait()):
                if event.died():
                    return event

    async def check(self) -> ChildEvent:
        death = await self.wait_for_exit()
        death.check()
        return death

    async def wait_for_stop_or_exit(self) -> ChildEvent:
        while True:
            for event in (await self.wait()):
                if event.died():
                    return event
                elif event.code == CLD.STOPPED:
                    return event

    async def send_signal(self, sig: Signals) -> None:
        await self.process.kill(sig)

    async def kill(self) -> None:
        await self.process.kill(Signals.SIGKILL)

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        if self.process.death_event:
            pass
        else:
            await self.kill()
            await self.wait_for_exit()

@dataclass(eq=False)
class SigchldWaiter:
    monitor: ChildProcessMonitorInternal
    got_sigchld: bool = False

    async def wait_for_sigchld(self) -> None:
        if not self.got_sigchld:
            await self.monitor.do_wait()

class ChildProcessMonitorInternal:
    def __init__(self, ram: RAM, signal_queue: SignalQueue, is_reaper: bool) -> None:
        self.ram = ram
        self.signal_queue = signal_queue
        self.is_reaper = is_reaper
        if self.signal_queue.signal_block.mask != set([Signals.SIGCHLD]):
            raise Exception("ChildProcessMonitor should get a SignalQueue only for SIGCHLD")
        self.running_wait = OneAtATime()
        self.waiters: t.List[SigchldWaiter] = []

    def add_task(self, process: handle.ChildProcess) -> AsyncChildProcess:
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
                    clone_task: handle.Task,
                    flags: CLONE,
                    child_stack: t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[handle.Pointer]=None) -> AsyncChildProcess:
        process = await clone_task.clone(flags|Signals.SIGCHLD, child_stack, None, ctid, None)
        return self.add_task(process)

    async def do_wait(self) -> None:
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                buf = await self.ram.malloc_struct(SignalfdSiginfo)
                # we don't care what information we get from the signal, we just want to
                # sleep until a SIGCHLD happens
                await self.signal_queue.read(buf)
                for waiter in self.waiters:
                    waiter.got_sigchld = True

@dataclass
class ChildProcessMonitor:
    internal: ChildProcessMonitorInternal
    cloning_task: handle.Task
    use_clone_parent: bool
    is_reaper: bool

    @staticmethod
    async def make(ram: RAM, task: handle.Task, epoller: EpollCenter,
                   *, signal_block: SignalBlock=None,
                   is_reaper: bool=False,
    ) -> ChildProcessMonitor:
        signal_queue = await SignalQueue.make(ram, task, epoller, Sigset({Signals.SIGCHLD}), signal_block=signal_block)
        monitor = ChildProcessMonitorInternal(ram, signal_queue, is_reaper=is_reaper)
        return ChildProcessMonitor(monitor, task, use_clone_parent=False, is_reaper=is_reaper)

    def inherit_to_child(self, child_task: handle.Task) -> ChildProcessMonitor:
        if self.is_reaper:
            # TODO we should actually look at something on the Task, I suppose, to determine if we're a reaper
            raise Exception("we're a ChildProcessMonitor for a reaper task, "
                            "we can't be inherited because we can't use CLONE_PARENT")
        if child_task.parent_task is not self.internal.signal_queue.sigfd.handle.task:
            raise Exception("task", child_task, "with parent_task", child_task.parent_task,
                            "is not our child; we're", self.internal.signal_queue.sigfd.handle.task)
        # we now know that the cloning task is in a process which is a child process of the waiting task.  so
        # we know that if use CLONE_PARENT while cloning in the cloning task, the resulting tasks will be
        # children of the waiting task, so we can use the waiting task to wait on them.
        return ChildProcessMonitor(self.internal, child_task, use_clone_parent=True, is_reaper=self.is_reaper)

    def inherit_to_thread(self, cloning_task: handle.Task) -> ChildProcessMonitor:
        if self.internal.signal_queue.sigfd.handle.task.process is not cloning_task.process:
            raise Exception("waiting task process", self.internal.signal_queue.sigfd.handle.task.process,
                            "is not the same as cloning task process", cloning_task.process)
        # we know that the cloning task is in the same process as the waiting task. so any children the
        # cloning task starts will also be waitable-on by the waiting task.
        return ChildProcessMonitor(self.internal, cloning_task, use_clone_parent=False, is_reaper=self.is_reaper)

    async def clone(self, flags: CLONE,
                    child_stack: t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]],
                    ctid: t.Optional[handle.Pointer[FutexNode]]=None) -> AsyncChildProcess:
        if self.use_clone_parent:
            flags |= CLONE.PARENT
        return (await self.internal.clone(self.cloning_task, flags, child_stack, ctid=ctid))
