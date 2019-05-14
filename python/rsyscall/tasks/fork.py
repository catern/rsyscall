from __future__ import annotations
from rsyscall._raw import ffi # type: ignore
from dataclasses import dataclass
from rsyscall.batch import BatchSemantics, perform_async_batch
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

from rsyscall.sched import CLONE
from rsyscall.signal import Signals
from rsyscall.sys.mman import PROT, MAP

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
                 server_task: AsyncChildProcess,
                 futex_task: t.Optional[AsyncChildProcess],
    ) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.server_task = server_task
        self.futex_task = futex_task
        self.identifier_process = self.server_task.process.near
        self.logger = logging.getLogger(f"rsyscall.ChildSyscallInterface.{int(self.server_task.process.near)}")
        self.running_read = OneAtATime()

    def store_remote_side_handles(self, infd: FileDescriptor, outfd: FileDescriptor) -> None:
        # these are needed so that we don't close them with garbage collection
        self.infd = infd
        self.outfd = outfd

    def get_activity_fd(self) -> FileDescriptor:
        return self.infd

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def _read_syscall_responses_direct(self) -> None:
        got_responses = False
        try:
            async with trio.open_nursery() as nursery:
                async def read_response() -> None:
                    self.logger.info("enter syscall response %s", self.rsyscall_connection.pending_responses)
                    await self.rsyscall_connection.read_pending_responses()
                    nonlocal got_responses
                    got_responses = True
                    self.logger.info("read syscall response %s", self.rsyscall_connection.pending_responses)
                    nursery.cancel_scope.cancel()
                async def server_exit() -> None:
                    # meaning the server exited
                    try:
                        self.logger.info("enter server exit")
                        await self.server_task.wait_for_exit()
                    except:
                        self.logger.info("out of server exit")
                        raise
                    raise ChildExit()
                async def futex_exit() -> None:
                    if self.futex_task is not None:
                        # meaning the server called exec or exited; we don't
                        # wait to see which one.
                        try:
                            self.logger.info("enter futex exit")
                            await self.futex_task.wait_for_exit()
                        except:
                            self.logger.info("out of futex exit")
                            raise
                        raise MMRelease()
                nursery.start_soon(read_response)
                nursery.start_soon(server_exit)
                nursery.start_soon(futex_exit)
        except:
            # if we got some responses, we shouldn't let this exception through;
            # instead we should process those syscall responses, and let the next syscall fail
            if not got_responses:
                raise
        else:
            self.logger.info("returning or raising syscall response from nursery")

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
    async def op(sem: BatchSemantics) -> t.Tuple[Pointer[Stack], WrittenPointer[Stack]]:
        stack_value = loader.make_trampoline_stack(Trampoline(
            loader.futex_helper_func, [
                int(futex_pointer.near + ffi.offsetof('struct futex_node', 'futex')),
                futex_pointer.value.futex]))
        stack_buf = sem.malloc_type(Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        return stack
    stack = await ram.perform_async_batch(op)
    futex_task = await monitor.clone(CLONE.VM|CLONE.FILES, stack)
    # wait for futex helper to SIGSTOP itself,
    # which indicates the trampoline is done and we can deallocate the stack.
    event = await futex_task.wait_for_stop_or_exit()
    if event.died():
        raise Exception("thread internal futex-waiting task died unexpectedly", event)
    # resume the futex_task so it can start waiting on the futex
    await futex_task.send_signal(Signals.SIGCONT)
    # the stack will be freed as it is no longer needed, but the futex pointer will live on
    return futex_task

async def spawn_rsyscall_thread(
        ram: RAM, task: Task,
        access_sock: AsyncFileDescriptor, remote_sock: FileDescriptor,
        monitor: ChildProcessMonitor,
        loader: NativeLoader,
        newuser: bool, newpid: bool, fs: bool, sighand: bool,
) -> Task:
    flags = CLONE.VM|CLONE.FILES|CLONE.IO|CLONE.SYSVSEM|Signals.SIGCHLD
    # TODO correctly track the namespaces we're in for all these things
    if newuser:
        flags |= CLONE.NEWUSER
    if newpid:
        flags |= CLONE.NEWPID
    if fs:
        flags |= CLONE.FS
    if sighand:
        flags |= CLONE.SIGHAND
    # TODO it is unclear why we sometimes need to make a new mapping here, instead of allocating with our normal
    # allocator; all our memory is already MAP.SHARED, I think.
    # We should resolve this so we can use the stock allocator.
    arena = Arena(await task.mmap(4096*2, PROT.READ|PROT.WRITE, MAP.SHARED))
    async def op(sem: BatchSemantics) -> t.Tuple[t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                                                       WrittenPointer[FutexNode]]:
        stack_value = loader.make_trampoline_stack(Trampoline(
            loader.server_func, [remote_sock, remote_sock]))
        stack_buf = sem.malloc_type(Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        futex_pointer = sem.to_pointer(FutexNode(None, Int32(0)))
        return stack, futex_pointer
    stack, futex_pointer = await perform_async_batch(task, ram.transport, arena, op)
    futex_process = await launch_futex_monitor(ram, loader, monitor, futex_pointer)
    child_process = await monitor.clone(flags|CLONE.CHILD_CLEARTID, stack, ctid=futex_pointer)

    syscall = ChildSyscallInterface(SyscallConnection(access_sock, access_sock), child_process, futex_process)
    if fs:
        fs_information = task.fs
    else:
        fs_information = far.FSInformation(child_process.process.near.id)
    if newpid:
        pidns = far.PidNamespace(child_process.process.near.id)
    else:
        pidns = task.pidns
    netns = task.netns
    real_parent_task = task.parent_task if monitor.use_clone_parent else task
    new_base_task = Task(syscall, child_process.process, real_parent_task,
                                task.fd_table, task.address_space, fs_information, pidns, netns)
    new_base_task.sigmask = task.sigmask
    remote_sock_handle = new_base_task.make_fd_handle(remote_sock)
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    return new_base_task

from rsyscall.epoller import EpollCenter
from rsyscall.network.connection import Connection, ConnectionThread
class ForkThread(ConnectionThread):
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 epoller: EpollCenter,
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

    async def _fork_task(self, newuser=False, newpid=False, fs=True, sighand=True) -> Task:
        [(access_sock, remote_sock)] = await self.connection.open_async_channels(1)
        base_task = await spawn_rsyscall_thread(
            self.ram, self.task.base,
            access_sock, remote_sock,
            self.child_monitor, self.loader,
            newuser=newuser, newpid=newpid, fs=fs, sighand=sighand,
        )
        await remote_sock.invalidate()
        return base_task


