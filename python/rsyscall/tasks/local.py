"""Resources in the local Python process
"""
from __future__ import annotations
from rsyscall.io import StandardTask, log_syscall
from rsyscall._raw import ffi, lib # type: ignore
import rsyscall.io as rsc
import trio
from rsyscall.handle import Task
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
from rsyscall.handle import Pointer
from rsyscall.signal import Signals, Sigaction, Sighandler
from rsyscall.sys.socket import AF, SOCK
import rsyscall.batch as batch
from rsyscall.network.connection import FDPassConnection
from rsyscall.environ import Environment
from rsyscall.loader import NativeLoader

from rsyscall.sys.epoll import EpollFlag
from rsyscall.epoller import EpollCenter

logger = logging.getLogger(__name__)

async def direct_syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
    "Make a syscall directly in the current thread."
    return lib.rsyscall_raw_syscall(ffi.cast('long', arg1), ffi.cast('long', arg2), ffi.cast('long', arg3),
                                    ffi.cast('long', arg4), ffi.cast('long', arg5), ffi.cast('long', arg6),
                                    number)

@dataclass
class LocalSyscallResponse(near.SyscallResponse):
    value: int
    async def receive(self) -> int:
        rsc.raise_if_error(self.value)
        return self.value


@dataclass(eq=False)
class LocalSyscall(near.SyscallInterface):
    identifier_process: near.Process

    def get_activity_fd(self) -> None:
        return None

    async def close_interface(self) -> None:
        pass

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> near.SyscallResponse:
        log_syscall(logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        result = await direct_syscall(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        return LocalSyscallResponse(result)

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        log_syscall(logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            result = await direct_syscall(
                number,
                arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
            rsc.raise_if_error(result)
        except Exception as exn:
            logger.debug("%s -> %s", number, exn)
            raise
        else:
            logger.debug("%s -> %s", number, result)
            return result

task: Task
class LocalMemoryTransport(handle.MemoryTransport):
    "This is a memory transport that only works on local pointers."
    def inherit(self, task: handle.Task) -> LocalMemoryTransport:
        return self

    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        for dest, data in ops:
            if dest.mapping.task.address_space != task.address_space:
                raise Exception("trying to write to pointer", dest, "not in local address space")
            ffi.memmove(ffi.cast('void*', int(dest.near)), data, len(data))

    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        ret: t.List[bytes] = []
        for src in ops:
            if src.mapping.task.address_space != task.address_space:
                raise Exception("trying to read from pointer", src, "not in local address space")
            buf = ffi.buffer(ffi.cast('void*', int(src.near)), src.bytesize())
            ret.append(bytes(buf))
        return ret

def _make_local_task() -> Task:
    pid = os.getpid()
    pid_namespace = far.PidNamespace(pid)
    process = far.Process(pid_namespace, near.Process(pid))
    base_task = handle.Task(
        LocalSyscall(process.near), process.near, None, far.FDTable(pid),
        far.AddressSpace(os.getpid()),
        far.FSInformation(pid),
        pid_namespace,
        far.NetNamespace(pid),
    )
    return base_task
def _make_local_function_handle(cffi_ptr) -> Pointer[loader.NativeFunction]:
    pointer_int = int(ffi.cast('ssize_t', cffi_ptr))
    # TODO we're just making up a memory mapping that this pointer is inside;
    # we should figure out the actual mapping, and the size for that matter.
    mapping = handle.MemoryMapping(task, near.MemoryMapping(pointer_int, 0, 1), near.File())
    return Pointer(mapping, loader.NullGateway(), loader.NativeFunctionSerializer(), loader.StaticAllocation())

async def _make_local_stdtask() -> StandardTask:
    local_transport = LocalMemoryTransport()
    ram = RAM(task, local_transport, memory.AllocatorClient.make_allocator(task))
    environ = {key.encode(): value.encode() for key, value in os.environ.items()}

    process_resources = NativeLoader(
        server_func=_make_local_function_handle(lib.rsyscall_server),
        persistent_server_func=_make_local_function_handle(lib.rsyscall_persistent_server),
        trampoline_func=_make_local_function_handle(lib.rsyscall_trampoline),
        futex_helper_func=_make_local_function_handle(lib.rsyscall_futex_helper),
    )
    epfd = await task.epoll_create(EpollFlag.CLOEXEC)
    async def wait_readable():
        logger.debug("wait_readable(%s)", epfd.near.number)
        await trio.hazmat.wait_readable(epfd.near.number)
    epoller = EpollCenter.make_subsidiary(ram, epfd, wait_readable)
    child_monitor = await rsc.ChildProcessMonitor.make(ram, task, epoller)
    access_connection = None
    connection = await FDPassConnection.make(task, ram, epoller)
    stdtask = StandardTask(
        task, ram,
        connection,
        process_resources,
        epoller, child_monitor,
        Environment(task, ram, environ),
        stdin=task.make_fd_handle(near.FileDescriptor(0)),
        stdout=task.make_fd_handle(near.FileDescriptor(1)),
        stderr=task.make_fd_handle(near.FileDescriptor(2)),
    )
    return stdtask

stdtask: StandardTask
async def _initialize_module() -> None:
    global stdtask
    stdtask = await _make_local_stdtask()
    # wipe out the SIGWINCH handler that the readline module installs
    import readline
    await stdtask.task.base.sigaction(
        Signals.SIGWINCH, await stdtask.ram.to_pointer(Sigaction(Sighandler.DFL)), None)

task = _make_local_task()
trio.run(_initialize_module)
thread = stdtask
