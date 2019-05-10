from rsyscall._raw import ffi # type: ignore
from dataclasses import dataclass
from rsyscall.batch import BatchSemantics, perform_async_batch
from rsyscall.concurrency import OneAtATime
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.exceptions import RsyscallException, RsyscallHangup
from rsyscall.handle import Stack, WrittenPointer, Pointer, FutexNode, FileDescriptor, Task, FutexNode
from rsyscall.loader import Trampoline, ProcessResources
from rsyscall.memory.allocator import Arena
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.struct import T_struct, Struct, Int32, Bytes
from rsyscall.tasks.common import raise_if_error, log_syscall
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
class SyscallResponse(near.SyscallResponse):
    process_one_response: t.Any
    result: t.Optional[t.Union[Exception, int]] = None

    async def receive(self) -> int:
        while self.result is None:
            await self.process_one_response()
        else:
            if isinstance(self.result, int):
                return self.result
            else:
                raise self.result

    def set_exception(self, exn: Exception) -> None:
        if self.result is not None:
            raise Exception("trying to set result on SyscallResponse twice")
        self.result = exn

    def set_result(self, result: int) -> None:
        if self.result is not None:
            raise Exception("trying to set result on SyscallResponse twice")
        self.result = result

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

    async def close(self) -> None:
        await self.tofd.aclose()
        await self.fromfd.aclose()

    async def write_request(self, number: int,
                            arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> None:
        request = RsyscallSyscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        ptr = await self.tofd.ram.to_pointer(request)
        try:
            await self.tofd.write_handle(ptr)
        except OSError as e:
            # we raise a different exception so that users can distinguish syscall errors from
            # transport errors
            raise RsyscallException() from e

    def poll_response(self) -> t.Optional[int]:
        val = self.buffer.read_struct(RsyscallResponse)
        if val:
            return val.value
        else:
            return None

    async def read_response(self) -> int:
        val = self.buffer.read_struct(RsyscallResponse)
        if val:
            return val.value
        buf = await self.fromfd.ram.malloc_type(Bytes, 256)
        while val is None:
            if self.valid is None:
                valid, rest = await self.fromfd.read_handle(buf)
                if valid.bytesize() == 0:
                    raise RsyscallHangup()
                self.valid = valid
            data = await self.valid.read()
            self.valid = None
            self.buffer.feed_bytes(data)
            buf = valid.merge(rest)
            val = self.buffer.read_struct(RsyscallResponse)
        return val.value

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
        self.infd: FileDescriptor
        self.outfd: FileDescriptor
        self.activity_fd: near.FileDescriptor
        self.request_lock = trio.Lock()
        self.pending_responses: t.List[SyscallResponse] = []
        self.running_read = OneAtATime()

    def store_remote_side_handles(self, infd: FileDescriptor, outfd: FileDescriptor) -> None:
        # these are needed so that we don't close them with garbage collection
        self.infd = infd
        self.outfd = outfd
        # this is part of the SyscallInterface
        self.activity_fd = infd.near

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def _read_syscall_response(self) -> int:
        # we poll first so that we don't unnecessarily issue waitids if we've
        # already got a response in our buffer
        response: t.Optional[int] = self.rsyscall_connection.poll_response()
        if response is not None:
            raise_if_error(response)
            return response
        try:
            async with trio.open_nursery() as nursery:
                async def read_response() -> None:
                    nonlocal response
                    response = await self.rsyscall_connection.read_response()
                    self.logger.info("read syscall response")
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
            # if response is not None, we shouldn't let this exception through;
            # instead we should process this syscall response, and let the next syscall fail
            if response is None:
                raise
        else:
            self.logger.info("returning or raising syscall response from nursery %s", response)
        if response is None:
            raise Exception("somehow made it out of the nursery without either throwing or getting a response")
        raise_if_error(response)
        return response

    async def _process_response_for(self, response: SyscallResponse) -> None:
        try:
            ret = await self._read_syscall_response()
            self.logger.info("returned syscall response %s", ret)
        except Exception as e:
            response.set_exception(e)
        else:
            response.set_result(ret)

    async def _process_one_response_direct(self) -> None:
        if len(self.pending_responses) == 0:
            raise Exception("somehow we are trying to process a syscall response, when there are no pending syscalls.")
        next = self.pending_responses[0]
        await self._process_response_for(next)
        self.pending_responses = self.pending_responses[1:]

    async def _process_one_response(self) -> None:
        async with self.running_read.needs_run() as needs_run:
            if needs_run:
                await self._process_one_response_direct()

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        async with self.request_lock:
            log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
            await self.rsyscall_connection.write_request(
                number,
                arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        response = SyscallResponse(self._process_one_response)
        self.pending_responses.append(response)
        return response

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            # we must not be interrupted while reading the response - we need to return
            # the response so that our parent can deal with the state change we created.
            with trio.CancelScope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

async def launch_futex_monitor(ram: RAM,
                               process_resources: ProcessResources, monitor: ChildProcessMonitor,
                               futex_pointer: WrittenPointer[FutexNode]) -> AsyncChildProcess:
    async def op(sem: BatchSemantics) -> t.Tuple[Pointer[Stack], WrittenPointer[Stack]]:
        stack_value = process_resources.make_trampoline_stack(Trampoline(
            process_resources.futex_helper_func, [
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
        process_resources: ProcessResources,
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
        stack_value = process_resources.make_trampoline_stack(Trampoline(
            process_resources.server_func, [remote_sock, remote_sock]))
        stack_buf = sem.malloc_type(Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        futex_pointer = sem.to_pointer(FutexNode(None, Int32(0)))
        return stack, futex_pointer
    stack, futex_pointer = await perform_async_batch(task, ram.transport, arena, op)
    futex_process = await launch_futex_monitor(ram, process_resources, monitor, futex_pointer)
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

