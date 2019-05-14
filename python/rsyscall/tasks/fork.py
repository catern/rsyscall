from __future__ import annotations
from rsyscall._raw import ffi # type: ignore
from dataclasses import dataclass
from rsyscall.batch import BatchSemantics, perform_async_batch
from rsyscall.concurrency import OneAtATime
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.exceptions import RsyscallException, RsyscallHangup
from rsyscall.handle import Stack, WrittenPointer, Pointer, FutexNode, FileDescriptor, Task, FutexNode
from rsyscall.loader import Trampoline, NativeLoader
from rsyscall.memory.allocator import Arena
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.struct import T_struct, Struct, Int32, Bytes, StructList
from rsyscall.tasks.util import raise_if_error, log_syscall
import logging
import rsyscall.far as far
import rsyscall.near as near
import trio
import typing as t

from rsyscall.sched import CLONE
from rsyscall.signal import Signals
from rsyscall.sys.mman import PROT, MAP

class ChildExit(RsyscallHangup):
    pass

class MMRelease(RsyscallHangup):
    pass

@dataclass
class RsyscallSyscall(Struct):
    number: int
    arg1: int
    arg2: int
    arg3: int
    arg4: int
    arg5: int
    arg6: int

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct rsyscall_syscall const*', {
            "sys": self.number,
            "args": (self.arg1, self.arg2, self.arg3, self.arg4, self.arg5, self.arg6),
        })))

    T = t.TypeVar('T', bound='RsyscallSyscall')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct rsyscall_syscall*', ffi.from_buffer(data))
        return cls(struct.sys,
                   struct.args[0], struct.args[1], struct.args[2],
                   struct.args[3], struct.args[4], struct.args[5])

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct rsyscall_syscall')

@dataclass
class RsyscallResponse(Struct):
    value: int

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('long const*', self.value)))

    T = t.TypeVar('T', bound='RsyscallResponse')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('long*', ffi.from_buffer(data))
        return cls(struct[0])

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('long')

@dataclass
class ConnectionResponse:
    result: t.Optional[int] = None

@dataclass
class ConnectionRequest:
    syscall: RsyscallSyscall
    response: t.Optional[ConnectionResponse] = None

class ReadBuffer:
    def __init__(self) -> None:
        self.buf = b""

    def feed_bytes(self, data: bytes) -> None:
        self.buf += data

    def read_struct(self, cls: t.Type[T_struct]) -> t.Optional[T_struct]:
        length = cls.sizeof()
        if length <= len(self.buf):
            section = self.buf[:length]
            self.buf = self.buf[length:]
            return cls.from_bytes(section)
        else:
            return None

    def read_all_structs(self, cls: t.Type[T_struct]) -> t.List[T_struct]:
        ret: t.List[T_struct] = []
        while True:
            x = self.read_struct(cls)
            if x is None:
                return ret
            ret.append(x)

class RsyscallConnection:
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 tofd: AsyncFileDescriptor,
                 fromfd: AsyncFileDescriptor,
    ) -> None:
        self.tofd = tofd
        self.fromfd = fromfd
        self.buffer = ReadBuffer()
        self.valid: t.Optional[Pointer[Bytes]] = None
        self.sending_requests = OneAtATime()
        self.pending_requests: t.List[ConnectionRequest] = []
        self.reading_responses = OneAtATime()
        self.pending_responses: t.List[ConnectionResponse] = []

    async def close(self) -> None:
        if self.pending_requests:
            # TODO we might want to do this, maybe we could cancel these instead?
            # note that we don't check responses - exit, for example, doesn't get a response...
            # TODO maybe we should cancel the response when we detect death of task in the enclosing classes?
            raise Exception("can't close while there are pending requests", self.pending_requests)
        await self.tofd.aclose()
        await self.fromfd.aclose()

    async def _write_pending_requests_direct(self) -> None:
        requests = self.pending_requests
        self.pending_requests = []
        syscalls = StructList(RsyscallSyscall, [request.syscall for request in requests])
        try:
            ptr = await self.tofd.ram.to_pointer(syscalls)
            # TODO should mark the requests complete incrementally as we write them out,
            # instead of only once all requests have been written out
            await self.tofd.write_handle(ptr)
        except OSError as e:
            # we raise a different exception so that users can distinguish syscall errors from
            # transport errors
            # TODO we should copy the exception to all the requesters,
            # not just the one calling us; otherwise they'll block forever.
            raise RsyscallException() from e

        responses = [ConnectionResponse() for _ in requests]
        for request, response in zip(requests, responses):
            request.response = response
        self.pending_responses += responses

    async def _write_pending_requests(self) -> None:
        async with self.sending_requests.needs_run() as needs_run:
            if needs_run:
                await self._write_pending_requests_direct()

    async def _write_request(self, syscall: RsyscallSyscall) -> ConnectionResponse:
        request = ConnectionRequest(syscall)
        self.pending_requests.append(request)
        # TODO as a hack, so we don't have to figure it out now, we don't allow
        # a syscall request to be cancelled before it's actually made. we could
        # make this work later, and that would reduce some blocking from waitid
        with trio.CancelScope(shield=True):
            while request.response is None:
                await self._write_pending_requests()
        return request.response

    async def write_request(self, number: int,
                            arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int
    ) -> ConnectionResponse:
        syscall = RsyscallSyscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        return (await self._write_request(syscall))

    def poll_response(self) -> t.Optional[int]:
        val = self.buffer.read_struct(RsyscallResponse)
        if val:
            return val.value
        else:
            return None

    def _got_responses(self, vals: t.List[RsyscallResponse]) -> None:
        responses = self.pending_responses[:len(vals)]
        self.pending_responses = self.pending_responses[len(vals):]
        for response, val in zip(responses, vals):
            response.result = val.value

    async def _read_pending_responses_direct(self) -> None:
        vals = self.buffer.read_all_structs(RsyscallResponse)
        if vals:
            self._got_responses(vals)
            return
        buf = await self.fromfd.ram.malloc_type(Bytes, 1024)
        while not vals:
            if self.valid is None:
                valid, rest = await self.fromfd.read_handle(buf)
                if valid.bytesize() == 0:
                    raise RsyscallHangup()
                self.valid = valid
            data = await self.valid.read()
            self.valid = None
            self.buffer.feed_bytes(data)
            buf = valid.merge(rest)
            vals = self.buffer.read_all_structs(RsyscallResponse)
        self._got_responses(vals)

    async def read_pending_responses(self) -> None:
        async with self.reading_responses.needs_run() as needs_run:
            if needs_run:
                await self._read_pending_responses_direct()

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

class ChildConnection(near.SyscallInterface):
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 rsyscall_connection: RsyscallConnection,
                 server_task: AsyncChildProcess,
                 futex_task: t.Optional[AsyncChildProcess],
    ) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.server_task = server_task
        self.futex_task = futex_task
        self.identifier_process = self.server_task.process.near
        self.logger = logging.getLogger(f"rsyscall.ChildConnection.{int(self.server_task.process.near)}")
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

    syscall = ChildConnection(RsyscallConnection(access_sock, access_sock), child_process, futex_process)
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


