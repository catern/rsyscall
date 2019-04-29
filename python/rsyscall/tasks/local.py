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
import rsyscall.base as base
import rsyscall.handle as handle
import logging
import os
import typing as t
from dataclasses import dataclass
import rsyscall.memory as memory
from rsyscall.signal import Signals, Sigaction, Sighandler
from rsyscall.sys.socket import AF, SOCK
import rsyscall.batch as batch

async def direct_syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
    "Make a syscall directly in the current thread."
    return lib.rsyscall_raw_syscall(ffi.cast('long', arg1), ffi.cast('long', arg2), ffi.cast('long', arg3),
                                    ffi.cast('long', arg4), ffi.cast('long', arg5), ffi.cast('long', arg6),
                                    number)

@dataclass(eq=False)
class LocalSyscall(base.SyscallInterface):
    identifier_process: near.Process
    activity_fd = None
    logger = logging.getLogger("rsyscall.LocalSyscall")
    async def close_interface(self) -> None:
        pass

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> near.SyscallResponse:
        raise Exception("not supported for local syscaller")

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            result = await self._syscall(
                number,
                arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

    async def _syscall(self, number: int, arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> int:
        ret = await direct_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        rsc.raise_if_error(ret)
        return ret

class LocalMemoryTransport(base.MemoryTransport):
    "This is a memory transport that only works on local pointers."
    def inherit(self, task: handle.Task) -> LocalMemoryTransport:
        return self

    async def batch_write(self, ops: t.List[t.Tuple[far.Pointer, bytes]]) -> None:
        for dest, data in ops:
            ffi.memmove(ffi.cast('void*', int(dest.near)), data, len(data))

    async def batch_read(self, ops: t.List[t.Tuple[far.Pointer, int]]) -> t.List[bytes]:
        ret: t.List[bytes] = []
        for src, n in ops:
            buf = ffi.buffer(ffi.cast('void*', int(src.near)), n)
            ret.append(bytes(buf))
        return ret

def _make_local_task() -> Task:
    pid = os.getpid()
    pid_namespace = far.PidNamespace(pid)
    process = far.Process(pid_namespace, near.Process(pid))
    base_task = handle.Task(
        LocalSyscall(process.near), process.near, base.FDTable(pid), base.local_address_space,
        far.FSInformation(pid),
        pid_namespace,
        far.NetNamespace(pid),
    )
    return base_task
def _make_local_function(cffi_object) -> rsc.FunctionPointer:
    return rsc.FunctionPointer(far.Pointer(task.address_space, near.Pointer(int(ffi.cast('long', cffi_object)))))
def _make_local_function_handle(cffi_ptr) -> handle.Pointer[handle.NativeFunction]:
    return handle.Pointer(
        task, rsc.NullGateway(), handle.NativeFunctionSerializer(),
        rsc.StaticAllocation(near.Pointer(int(ffi.cast('ssize_t', cffi_ptr)))))

async def _make_local_stdtask() -> StandardTask:
    local_transport = LocalMemoryTransport()
    mem_task = rsc.Task(task,
                        local_transport,
                        memory.AllocatorClient.make_allocator(task),
                        rsc.SignalMask(set()))
    environ = {key.encode(): value.encode() for key, value in os.environ.items()}

    process_resources = rsc.ProcessResources(
        server_func=_make_local_function(lib.rsyscall_server),
        persistent_server_func=_make_local_function(lib.rsyscall_persistent_server),
        do_cloexec_func=_make_local_function_handle(lib.rsyscall_do_cloexec),
        stop_then_close_func=_make_local_function(lib.rsyscall_stop_then_close),
        trampoline_func=_make_local_function_handle(lib.rsyscall_trampoline),
        futex_helper_func=_make_local_function(lib.rsyscall_futex_helper),
    )
    filesystem_resources = rsc.FilesystemResources.make_from_environ(task, environ)
    epoller = await mem_task.make_epoll_center()
    child_monitor = await rsc.ChildProcessMonitor.make(mem_task, epoller)
    access_connection = None
    left_fd, right_fd = await mem_task.socketpair(AF.UNIX, SOCK.STREAM, 0)
    connecting_connection = (left_fd.handle, right_fd.handle)
    stdtask = StandardTask(
        mem_task, epoller, access_connection,
        mem_task, connecting_connection,
        mem_task, process_resources, filesystem_resources,
        epoller, child_monitor,
        {**environ},
        stdin=mem_task._make_fd(0, rsc.ReadableFile()),
        stdout=mem_task._make_fd(1, rsc.WritableFile()),
        stderr=mem_task._make_fd(2, rsc.WritableFile()),
    )
    # We don't need this ourselves, but we keep it around so others can inherit it.
    [(access_sock, remote_sock)] = await stdtask.make_async_connections(1)
    mem_task.transport = rsc.SocketMemoryTransport(access_sock, remote_sock, local_transport)
    return stdtask

stdtask: StandardTask
async def _initialize_module() -> None:
    global stdtask
    stdtask = await _make_local_stdtask()
    # wipe out the SIGWINCH handler that the readline module installs
    import readline
    await stdtask.task.base.sigaction(
        Signals.SIGWINCH, await stdtask.task.to_pointer(Sigaction(Sighandler.DFL)), None)

task = _make_local_task()
trio.run(_initialize_module)
