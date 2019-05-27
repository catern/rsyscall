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
import rsyscall.near as near
import rsyscall.handle as handle
import rsyscall.loader as loader
import logging
import os
import typing as t
from dataclasses import dataclass
import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM
from rsyscall.handle import Pointer, Task, MemoryMapping
from rsyscall.signal import SIG, Sigaction, Sighandler
from rsyscall.sys.socket import AF, SOCK
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

class LocalSyscallResponse(near.SyscallResponse):
    "Dummy SyscallResponse for local syscalls"
    def __init__(self, result_func: t.Callable[[], int]) -> None:
        self.result_func = result_func

    async def receive(self) -> int:
        return self.result_func()

class LocalSyscall(near.SyscallInterface):
    "Makes syscalls in the local, Python interpreter thread"
    def get_activity_fd(self) -> None:
        return None

    async def close_interface(self) -> None:
        pass

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> near.SyscallResponse:
        """Make a syscall immediately, returning LocalSyscallResponse already containing the result

        We can't actually implement the submit_syscall API for local syscalls, so we just
        immediately make the syscall and pack the response into a dummy SyscallResponse.

        """
        try:
            ret = await self.syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        except OSError as exn:
            def f() -> int:
                raise exn
        else:
            def f() -> int:
                return ret
        return LocalSyscallResponse(f)

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        log_syscall(logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            result = await _direct_syscall(
                number,
                arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
            raise_if_error(result)
        except Exception as exn:
            logger.debug("%s -> %s", number, exn)
            raise
        else:
            logger.debug("%s -> %s", number, result)
            return result

class LocalMemoryTransport(handle.MemoryTransport):
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
            buf = ffi.buffer(ffi.cast('void*', int(src.near)), src.bytesize())
            ret.append(bytes(buf))
        return ret

async def _make_local_thread() -> Thread:
    process = near.Process(os.getpid())
    task = Task(
        LocalSyscall(), process, None, far.FDTable(process.id),
        far.AddressSpace(process.id),
        far.PidNamespace(process.id),
    )
    ram = RAM(task, LocalMemoryTransport(task), memory.AllocatorClient.make_allocator(task))
    epfd = await task.epoll_create()
    async def wait_readable():
        logger.debug("wait_readable(%s)", epfd.near.number)
        await trio.hazmat.wait_readable(epfd.near.number)
    epoller = Epoller.make_subsidiary(ram, epfd, wait_readable)
    thread = Thread(
        task, ram,
        await FDPassConnection.make(task, ram, epoller),
        NativeLoader.make_from_symbols(task, lib),
        epoller,
        await ChildProcessMonitor.make(ram, task, epoller),
        Environment(task, ram, {key.encode(): value.encode() for key, value in os.environ.items()}),
        stdin=task.make_fd_handle(near.FileDescriptor(0)),
        stdout=task.make_fd_handle(near.FileDescriptor(1)),
        stderr=task.make_fd_handle(near.FileDescriptor(2)),
    )
    return thread

async def _initialize() -> Thread:
    thr = await _make_local_thread()
    # wipe out the SIGWINCH handler that the readline module installs
    import readline
    await thr.task.sigaction(SIG.WINCH, await thr.ram.ptr(Sigaction(Sighandler.DFL)), None)
    return thr

thread: Thread = trio.run(_initialize)
