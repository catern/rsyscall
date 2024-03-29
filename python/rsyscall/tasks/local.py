"""The local process, based on the local Python interpreter process.

The local process is the process that every rsyscall program has available from the
start. From this process, we create all the others.

"""
from __future__ import annotations
from dneio.core import TrioSystemWaitReadable, set_trio_system_wait_readable
from rsyscall.thread import Process
from rsyscall._raw import ffi, lib # type: ignore
import trio
import rsyscall.far as far
from rsyscall.near.sysif import SyscallInterface, Syscall, raise_if_error
import rsyscall.near.types as near
import rsyscall.handle as handle
import rsyscall.loader as loader
import logging
import os
import typing as t
from dataclasses import dataclass
import rsyscall.memory.allocator as memory
from rsyscall.handle import Pointer, Task
from rsyscall.signal import SIG, Sigaction, Sighandler
from rsyscall.sys.socket import AF, SOCK
from rsyscall.sys.syscall import SYS
from rsyscall.network.connection import FDPassConnection
from rsyscall.environ import Environment
from rsyscall.loader import NativeLoader
from rsyscall.monitor import ChildPidMonitor

from rsyscall.sys.epoll import EpollFlag
from rsyscall.epoller import Epoller

logger = logging.getLogger(__name__)

async def _direct_syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
    "Make a syscall directly in the current process."
    return lib.rsyscall_raw_syscall(arg1, arg2, arg3, arg4, arg5, arg6, number)

class LocalSyscall(SyscallInterface):
    "Makes syscalls in the local, Python interpreter process."
    def __init__(self, local_task: Task) -> None:
        self.local_task = local_task
        self.logger = logger

    def get_activity_fd(self) -> None:
        return None

    async def close_interface(self) -> None:
        pass

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        syscall = Syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        self.logger.debug("%s", syscall)
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

    async def write(self, dest: Pointer, data: bytes) -> None:
        if dest.mapping.task.address_space != self.local_task.address_space:
            raise Exception("trying to write to pointer", dest, "not in local address space")
        ffi.memmove(ffi.cast('void*', int(dest.near)), data, len(data))

    async def read(self, src: Pointer) -> bytes:
        if src.mapping.task.address_space != self.local_task.address_space:
            raise Exception("trying to read from pointer", src, "not in local address space")
        buf = ffi.buffer(ffi.cast('void*', int(src.near)), src.size())
        return bytes(buf)

    async def barrier(self) -> None:
        # when all writes are performed immediately, barrier is a no-op!
        pass

async def _make_local_process() -> Process:
    """Create the local process, allocating various resources locally.

    For the most part, the local process is like any other process; it just bootstraps
    differently, and uses syscall and memory interfaces which are specialized to the local
    process.

    """
    pid = near.Pid(os.getpid())
    task = Task(
        pid, handle.FDTable(pid.id),
        far.AddressSpace(pid.id),
        far.PidNamespace(pid.id),
        far.MountNamespace(pid.id),
    )
    task.sysif = LocalSyscall(task)
    task.allocator = await memory.AllocatorClient.make_allocator(task)
    epfd = await task.epoll_create()
    async def wait_readable():
        logger.debug("wait_readable(%s)", epfd.near.number)
        await trio.lowlevel.wait_readable(epfd.near.number)
    trio_system_wait_readable = TrioSystemWaitReadable(epfd.near.number)
    set_trio_system_wait_readable(trio_system_wait_readable)
    epoller = Epoller.make_subsidiary(epfd, trio_system_wait_readable.wait)
    process = Process(
        task,
        await FDPassConnection.make(task, epoller),
        NativeLoader.make_from_symbols(task, lib),
        epoller,
        await ChildPidMonitor.make(task, epoller),
        Environment.make_from_environ(task, {**os.environ}),
        stdin=task.make_fd_handle(near.FileDescriptor(0)),
        stdout=task.make_fd_handle(near.FileDescriptor(1)),
        stderr=task.make_fd_handle(near.FileDescriptor(2)),
    )
    return process

async def _initialize() -> Process:
    thr = await _make_local_process()
    # Wipe out the SIGWINCH handler that the readline module installs.
    # We do this because otherwise this handler will be inherited down to our
    # children, where it will segfault on run due to the environment being
    # totally different (lacking TLS for one). I'm not sure if there's any
    # alternative; wiping out the signal handlers from within the children after
    # they've been created still leaves a window for the signal handler to run.
    import readline
    await thr.task.sigaction(SIG.WINCH, await thr.task.ptr(Sigaction(Sighandler.DFL)), None)
    return thr

local_process: Process = trio.run(_initialize)
"The local process, fully initialized at import time"
