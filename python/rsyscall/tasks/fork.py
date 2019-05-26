from __future__ import annotations
from rsyscall._raw import ffi # type: ignore
from dataclasses import dataclass
from rsyscall.concurrency import OneAtATime
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.tasks.exceptions import RsyscallHangup
from rsyscall.handle import Stack, WrittenPointer, Pointer, FutexNode, FileDescriptor, Task, FutexNode
from rsyscall.loader import Trampoline, NativeLoader
from rsyscall.memory.allocator import Arena
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.tasks.util import raise_if_error, log_syscall
from rsyscall.tasks.connection import ConnectionResponse, SyscallConnection
import logging
import rsyscall.far as far
import rsyscall.near as near
import trio
import typing as t
from rsyscall.struct import Int32
import contextlib

from rsyscall.sched import CLONE
from rsyscall.signal import SIG
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sys.wait import W

class ChildExit(RsyscallHangup):
    pass

class MMRelease(RsyscallHangup):
    pass

@dataclass
class SyscallResponse(near.SyscallResponse):
    process_responses: t.Any
    response: ConnectionResponse

    async def receive(self, logger=None) -> int:
        while self.response.result is None:
            if logger:
                logger.info("no response yet for %s, calling process responses", self.response)
            await self.process_responses()
            if logger:
                logger.info("exited process responses for %s", self.response)
        raise_if_error(self.response.result)
        return self.response.result

class ChildSyscallInterface(near.SyscallInterface):
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 rsyscall_connection: SyscallConnection,
                 server_process: AsyncChildProcess,
                 futex_process: t.Optional[AsyncChildProcess],
    ) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.server_process = server_process
        self.futex_process = futex_process
        self.identifier_process = self.server_process.process.near
        self.logger = logging.getLogger(f"rsyscall.ChildSyscallInterface.{int(self.server_process.process.near)}")
        self.running_read = OneAtATime()

    def store_remote_side_handles(self, infd: FileDescriptor, outfd: FileDescriptor) -> None:
        # these are needed so that we don't close them with garbage collection
        self.infd = infd
        self.outfd = outfd

    def get_activity_fd(self) -> FileDescriptor:
        return self.infd

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()
        self.infd._invalidate()
        self.outfd._invalidate()

    @contextlib.asynccontextmanager
    async def _throw_on_child_exit(self) -> t.AsyncGenerator[None, None]:
        child_exited = False
        futex_exited = False
        got_result = False
        async with trio.open_nursery() as nursery:
            async def server_exit() -> None:
                await self.server_process.waitpid(W.EXITED)
                nonlocal child_exited
                child_exited = True
                nursery.cancel_scope.cancel()
            async def futex_exit() -> None:
                if self.futex_process is not None:
                    await self.futex_process.waitpid(W.EXITED)
                    nonlocal futex_exited
                    futex_exited = True
                    nursery.cancel_scope.cancel()
            nursery.start_soon(server_exit)
            nursery.start_soon(futex_exit)
            yield
            got_result = True
            nursery.cancel_scope.cancel()
        if got_result:
            return
        elif child_exited:
            # this takes precedence over MMRelease, since it gives us more information
            raise ChildExit()
        elif futex_exited:
            raise MMRelease()

    async def _read_syscall_responses_direct(self) -> None:
        async with self._throw_on_child_exit():
            await self.rsyscall_connection.read_pending_responses()
        self.logger.info("returning after reading some syscall responses")

    async def _read_syscall_responses(self) -> None:
        async with self.running_read.needs_run() as needs_run:
            if needs_run:
                self.logger.info("running read_syscall_responses_direct")
                await self._read_syscall_responses_direct()
                self.logger.info("done with read_syscall_responses_direct")

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        conn_response = await self.rsyscall_connection.write_request(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        response = SyscallResponse(self._read_syscall_responses, conn_response)
        return response

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            # we must not be interrupted while reading the response - we need to return
            # the response so that our parent can deal with the state change we created.
            with trio.CancelScope(shield=True):
                result = await response.receive(self.logger)
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

async def launch_futex_monitor(ram: RAM,
                               loader: NativeLoader, monitor: ChildProcessMonitor,
                               futex_pointer: WrittenPointer[FutexNode]) -> AsyncChildProcess:
    async def op(sem: RAM) -> t.Tuple[Pointer[Stack], WrittenPointer[Stack]]:
        stack_value = loader.make_trampoline_stack(Trampoline(
            loader.futex_helper_func, [
                int(futex_pointer.near + ffi.offsetof('struct futex_node', 'futex')),
                futex_pointer.value.futex]))
        stack_buf = await sem.malloc(Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        return stack
    stack = await ram.perform_batch(op)
    futex_process = await monitor.clone(CLONE.VM|CLONE.FILES, stack)
    # wait for futex helper to SIGSTOP itself,
    # which indicates the trampoline is done and we can deallocate the stack.
    state = await futex_process.waitpid(W.EXITED|W.STOPPED)
    if state.state(W.EXITED):
        raise Exception("thread internal futex-waiting task died unexpectedly", state)
    # resume the futex_process so it can start waiting on the futex
    await futex_process.kill(SIG.CONT)
    # the stack will be freed as it is no longer needed, but the futex pointer will live on
    return futex_process

async def spawn_child_task(
        task: Task, ram: RAM,
        loader: NativeLoader,
        monitor: ChildProcessMonitor,
        access_sock: AsyncFileDescriptor,
        remote_sock: FileDescriptor,
        trampoline: Trampoline,
        flags: CLONE,
) -> t.Tuple[AsyncChildProcess, Task]:
    flags |= CLONE.VM|CLONE.FILES|CLONE.IO|CLONE.SYSVSEM|SIG.CHLD
    # TODO it is unclear why we sometimes need to make a new mapping here, instead of allocating with our normal
    # allocator; all our memory is already MAP.SHARED, I think.
    # We should resolve this so we can use the stock allocator.
    arena = Arena(await task.mmap(4096*2, PROT.READ|PROT.WRITE, MAP.SHARED))
    async def op(sem: RAM) -> t.Tuple[t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                                                       WrittenPointer[FutexNode]]:
        stack_value = loader.make_trampoline_stack(trampoline)
        stack_buf = await sem.malloc(Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        futex_pointer = await sem.ptr(FutexNode(None, Int32(0)))
        return stack, futex_pointer
    stack, futex_pointer = await ram.perform_batch(op, arena)
    # it's important to start the processes in this order, so that the thread process
    # is the first process started if we unshare NEWPID, and therefore becomes pid 1.
    # rather than the futex process becoming pid 1...
    child_process = await monitor.clone(flags|CLONE.CHILD_CLEARTID, stack, ctid=futex_pointer)
    futex_process = await launch_futex_monitor(ram, loader, monitor, futex_pointer)

    syscall = ChildSyscallInterface(SyscallConnection(access_sock, access_sock), child_process, futex_process)
    # TODO correctly track all the namespaces we're in
    if flags & CLONE.NEWPID:
        pidns = far.PidNamespace(child_process.process.near.id)
    else:
        pidns = task.pidns
    real_parent_task = task.parent_task if monitor.use_clone_parent else task
    new_base_task = Task(syscall, child_process.process, real_parent_task,
                         task.fd_table, task.address_space, pidns)
    new_base_task.sigmask = task.sigmask
    remote_sock_handle = new_base_task.make_fd_handle(remote_sock)
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    return child_process, new_base_task

async def spawn_rsyscall_thread(
        ram: RAM, task: Task,
        access_sock: AsyncFileDescriptor, remote_sock: FileDescriptor,
        monitor: ChildProcessMonitor,
        loader: NativeLoader,
        flags: CLONE,
) -> t.Tuple[AsyncChildProcess, Task]:
    return await spawn_child_task(
        task, ram, loader, monitor, access_sock, remote_sock,
        Trampoline(loader.server_func, [remote_sock, remote_sock]), flags)

from rsyscall.epoller import Epoller
from rsyscall.network.connection import Connection, ConnectionThread
class ForkThread(ConnectionThread):
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 epoller: Epoller,
                 connection: Connection,
                 loader: NativeLoader,
                 child_monitor: ChildProcessMonitor,
    ) -> None:
        super().__init__(task, ram, epoller, connection)
        self.loader = loader
        self.child_monitor = child_monitor

    def _init_from(self, thr: ForkThread) -> None: # type: ignore
        super()._init_from(thr)
        self.loader = thr.loader
        self.child_monitor = thr.child_monitor

    async def _fork_task(self, flags: CLONE) -> t.Tuple[AsyncChildProcess, Task]:
        [(access_sock, remote_sock)] = await self.connection.open_async_channels(1)
        child_process, base_task = await spawn_rsyscall_thread(
            self.ram, self.task,
            access_sock, remote_sock,
            self.child_monitor, self.loader,
            flags,
        )
        await remote_sock.invalidate()
        return child_process, base_task


