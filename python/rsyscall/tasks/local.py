"""The local thread, based on the local Python interpreter thread.

The local thread is the thread that every rsyscall program has available from the
start. From this thread, we create all the others.

"""
from __future__ import annotations
from rsyscall.thread import Thread
from rsyscall.tasks.util import log_syscall, raise_if_error
from rsyscall._raw import ffi, lib # type: ignore
import trio
import rsyscall.far as far
from rsyscall.near.sysif import SyscallInterface, SyscallResponse
import rsyscall.near.types as near
import rsyscall.handle as handle
import rsyscall.loader as loader
import logging
import os
import typing as t
from dataclasses import dataclass
import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM
from rsyscall.memory.transport import MemoryTransport
from rsyscall.handle import Pointer, Task
from rsyscall.signal import SIG, Sigaction, Sighandler
from rsyscall.sys.socket import AF, SOCK
from rsyscall.sys.syscall import SYS
from rsyscall.network.connection import FDPassConnection
from rsyscall.environ import Environment
from rsyscall.loader import NativeLoader
from rsyscall.monitor import ChildProcessMonitor

from rsyscall.sys.epoll import EpollFlag
from rsyscall.epoller import Epoller

logger = logging.getLogger(__name__)

__all__ = [
    "thread",
]

async def _direct_syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
    "Make a syscall directly in the current thread."
    return lib.rsyscall_raw_syscall(arg1, arg2, arg3, arg4, arg5, arg6, number)

class LocalSyscallResponse(SyscallResponse):
    "Dummy SyscallResponse for local syscalls."
    def __init__(self, result_func: t.Callable[[], int]) -> None:
        self.result_func = result_func

    async def receive(self) -> int:
        return self.result_func()

class LocalSyscall(SyscallInterface):
    "Makes syscalls in the local, Python interpreter thread."
    def __init__(self) -> None:
        self.logger = logger

    def get_activity_fd(self) -> None:
        return None

    async def close_interface(self) -> None:
        pass

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        """Send a syscall and wait for it to complete, throwing on error results.

        See SyscallInterface.syscall.

        SyscallInterface provides a default implementation for this method, but we override it for performance reasons;
        since we immediately get the result, we don't need to create a trio.CancelScope as SyscallInterface.syscall
        does, which is sadly quite expensive.

        """
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        result = await _direct_syscall(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        try:
            raise_if_error(result)
        except OSError as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        self.logger.debug("%s -> %s", number, result)
        return result

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> LocalSyscallResponse:
        """Make a syscall in the local thread; return SyscallResponse already containing the result.

        We can't actually implement the submit_syscall API for local syscalls, so we just
        immediately make the syscall and pack the response into a dummy SyscallResponse.

        Linux returns errors as just another kind of syscall return value. A certain range
        of possible syscall return values (-4095 to 0, not inclusive) indicates an error;
        we call raise_if_error to check and throw if we're in that range.

        """
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        result = await _direct_syscall(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        def f(result=result) -> int:
            raise_if_error(result)
            return result
        return LocalSyscallResponse(f)

class LocalMemoryTransport(MemoryTransport):
    "This is a memory transport that only works on local pointers."
    def __init__(self, local_task: Task) -> None:
        self.local_task = local_task

    def inherit(self, task: Task) -> LocalMemoryTransport:
        return self

    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        for dest, data in ops:
            if dest.mapping.task.address_space != self.local_task.address_space:
                raise Exception("trying to write to pointer", dest, "not in local address space")
            ffi.memmove(ffi.cast('void*', int(dest.near)), data, len(data))

    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        ret: t.List[bytes] = []
        for src in ops:
            if src.mapping.task.address_space != self.local_task.address_space:
                raise Exception("trying to read from pointer", src, "not in local address space")
            buf = ffi.buffer(ffi.cast('void*', int(src.near)), src.size())
            ret.append(bytes(buf))
        return ret

async def _make_local_thread() -> Thread:
    """Create the local thread, allocating various resources locally.

    For the most part, the local thread is like any other thread; it just bootstraps
    differently, and uses syscall and memory interfaces which are specialized to the local
    thread.

    """
    process = near.Process(os.getpid())
    task = Task(
        process, handle.FDTable(process.id),
        far.AddressSpace(process.id),
        far.PidNamespace(process.id),
    )
    task.sysif = LocalSyscall()
    ram = RAM(task, LocalMemoryTransport(task), memory.AllocatorClient.make_allocator(task))
    epfd = await task.epoll_create()
    async def wait_readable():
        logger.debug("wait_readable(%s)", epfd.near.number)
        await trio.lowlevel.wait_readable(epfd.near.number)
    epoller = Epoller.make_subsidiary(ram, epfd, wait_readable)
    thread = Thread(
        task, ram,
        await FDPassConnection.make(task, ram, epoller),
        NativeLoader.make_from_symbols(task, lib),
        epoller,
        await ChildProcessMonitor.make(ram, task, epoller),
        Environment.make_from_environ(task, ram, {**os.environ}),
        stdin=task.make_fd_handle(near.FileDescriptor(0)),
        stdout=task.make_fd_handle(near.FileDescriptor(1)),
        stderr=task.make_fd_handle(near.FileDescriptor(2)),
    )
    return thread

async def _initialize() -> Thread:
    thr = await _make_local_thread()
    # Wipe out the SIGWINCH handler that the readline module installs.
    # We do this because otherwise this handler will be inherited down to our
    # children, where it will segfault on run due to the environment being
    # totally different (lacking TLS for one). I'm not sure if there's any
    # alternative; wiping out the signal handlers from within the children after
    # they've been created still leaves a window for the signal handler to run.
    import readline
    await thr.task.sigaction(SIG.WINCH, await thr.ram.ptr(Sigaction(Sighandler.DFL)), None)
    return thr

thread: Thread = trio.run(_initialize)
"The local thread, fully initialized at import time"
