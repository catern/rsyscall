"""The rsyscall protocol implementation

That's a bit grandiose, because the rsyscall protocol is extremely simple: Write
a syscall request out as a fixed-size struct containing a syscall number and the
arguments, read the syscall response in as a 64-bit long.

Still, it's not completely trivial, because we do pipelining of syscall
requests, and we also batch together multiple requests so they can be written
out all at once.

"""
from rsyscall._raw import ffi # type: ignore
from dataclasses import dataclass
from rsyscall.handle import Pointer, Task, WrittenPointer
from rsyscall.concurrency import SuspendableCoroutine, Future, Promise, make_future, FIFOFuture, FIFOPromise
from rsyscall.concurrency import CoroQueue, trio_op, trio_runner
from rsyscall.struct import T_fixed_size, Struct, Int32, StructList
from rsyscall.epoller import AsyncFileDescriptor, AsyncReadBuffer, EOFException
from rsyscall.near.sysif import SyscallHangup, syscall_snd_callback
import abc
import contextlib
import math
import typing as t
import trio
import outcome

__all__ = [
    "SyscallConnection",
    "ConnectionResponse",
    "Syscall",
]

import logging
logger = logging.getLogger(__name__)
class ConnectionError(SyscallHangup):
    "Something has gone wrong with the rsyscall connection"
    pass

@dataclass
class Syscall(Struct):
    "The struct representing a syscall request"
    number: t.SupportsInt
    arg1: t.SupportsInt
    arg2: t.SupportsInt
    arg3: t.SupportsInt
    arg4: t.SupportsInt
    arg5: t.SupportsInt
    arg6: t.SupportsInt

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct rsyscall_syscall const*', {
            "sys": self.number,
            "args": (self.arg1, self.arg2, self.arg3, self.arg4, self.arg5, self.arg6),
        })))

    T = t.TypeVar('T', bound='Syscall')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct rsyscall_syscall*', ffi.from_buffer(data))
        return cls(int(struct.sys),
                   int(struct.args[0]), int(struct.args[1]), int(struct.args[2]),
                   int(struct.args[3]), int(struct.args[4]), int(struct.args[5]))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct rsyscall_syscall')

@dataclass
class SyscallResponse(Struct):
    "The struct representing a syscall response"
    value: int

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('long const*', self.value)))

    T = t.TypeVar('T', bound='SyscallResponse')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('long*', ffi.from_buffer(data))
        return cls(struct[0])

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('long')

@dataclass
class ConnectionRequest:
    syscall: Syscall
    response_future: Future[FIFOFuture[int]]
    response_promise: Promise[FIFOFuture[int]]
    result_suspendable: t.Optional[SuspendableCoroutine]

class ReadBuffer:
    "A simple buffer for deserializing structs"
    def __init__(self, task: Task) -> None:
        # To read and write structures, we have to know what task
        # they're coming from.
        self.task = task
        self.buf = b""

    def feed_bytes(self, data: bytes) -> None:
        self.buf += data

    def read_struct(self, cls: t.Type[T_fixed_size]) -> t.Optional[T_fixed_size]:
        "Read one fixed-size struct from the buffer, or return None if that's not possible"
        length = cls.sizeof()
        if length <= len(self.buf):
            section = self.buf[:length]
            self.buf = self.buf[length:]
            return cls.get_serializer(self.task).from_bytes(section)
        else:
            return None

    def read_all_structs(self, cls: t.Type[T_fixed_size]) -> t.List[T_fixed_size]:
        "Read as many fixed-size structs from the buffer as possible"
        ret: t.List[T_fixed_size] = []
        while True:
            x = self.read_struct(cls)
            if x is None:
                return ret
            ret.append(x)
    
async def add_batch_to_list(requests: t.List, chan: trio.abc.ReceiveChannel) -> t.List:
    # if there are no current requests, block until there's something to do
    if not requests:
        requests.append(await chan.receive())
    # grab everything else in the channel
    try:
        while True:
            requests.append(chan.receive_nowait())
    except (trio.WouldBlock, trio.Cancelled):
        return requests

def find_uncancelled_part(
        ptr: WrittenPointer[StructList[Syscall]],
        reqs: t.List[ConnectionRequest],
) -> t.Tuple[
    t.Optional[t.Tuple[
        WrittenPointer[StructList[Syscall]], t.List[ConnectionRequest],
    ]],
    t.List[ConnectionRequest],
]:
    """Finds the first part of this pointer referring to uncancelled ConnectionRequests

    Also returns all other uncancelled requests not covered by that pointer.

    Don't fear the type signature, it's really quite simple!
    """
    # TODO actually support cancellation of syscall requests...
    return (ptr, reqs), []

class ConnectionDefunctMonitor:
    @abc.abstractmethod
    def throw_on_connection_defunct(self) -> t.AsyncContextManager: ...

class ConnectionDefunctOnlyOnEOF(ConnectionDefunctMonitor):
    @contextlib.asynccontextmanager
    async def throw_on_connection_defunct(self) -> t.AsyncGenerator[None, None]:
        yield

import functools

class SyscallConnection:
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 tofd: AsyncFileDescriptor,
                 fromfd: AsyncFileDescriptor,
                 defunct_monitor: t.Optional[ConnectionDefunctMonitor],
    ) -> None:
        self.tofd = tofd
        self.fromfd = fromfd
        self.buffer = ReadBuffer(self.fromfd.handle.task)
        self.valid: t.Optional[Pointer[bytes]] = None
        self.request_queue = CoroQueue.start(self._run_requests)
        self.response_queue = CoroQueue.start(self._run_responses)
        self.defunct_monitor = defunct_monitor or ConnectionDefunctOnlyOnEOF()

    async def close(self) -> None:
        "Close this SyscallConnection; will throw if there are pending requests"
        if self.request_queue._waiting:
            # TODO we might want to do this, maybe we could cancel these instead?
            # note that we don't check responses - exit, for example, doesn't get a response...
            # TODO maybe we should cancel the response when we detect death of task in the enclosing classes?
            raise Exception("can't close while there are pending requests", self.request_queue._waiting)
        await self.tofd.close()
        await self.fromfd.close()

    async def do_syscall(self, syscall: Syscall) -> int:
        """Write a syscall request, returning a Future for the result.

        """
        # TODO as a hack, so we don't have to figure it out now, we don't allow
        # a syscall request to be cancelled before it's actually made. we could
        # make this work later, and that would reduce some blocking from waitid
        in_trio = not await trio_runner.get()
        logger.debug("do_syscall: %s", syscall)
        if in_trio:
            with trio.CancelScope(shield=True):
                # hmm this cancel scope shields the entire thing. unfortunate...
                return await self.request_queue.send_request(syscall)
        else:
            return await self.request_queue.send_request(syscall)

    async def _run_requests(self, queue: CoroQueue) -> None:
        while True:
            # wait until we have a batch to do, received from self.pending_requests
            requests = await queue.get_many()
            logger.info("_run_requests: get_many: %s", requests)
            # write remaining_reqs to memory
            ptr: Pointer[StructList] = await trio_op(
                self.tofd.ram.ptr, StructList(Syscall, [syscall for syscall, coro in requests]))
            logger.info("_run_requests: performed ptr for: %s", requests)
            ptr_to_write, reqs_to_write = ptr, requests
            # TODO write requests to tofd in parallel with receiving more
            # requests from the channel and writing them to memory
            try:
                try:
                    while ptr_to_write.size() > 0:
                        _, ptr_to_write = await trio_op(self.tofd.write, ptr_to_write)
                        # TODO mark the requests as complete incrementally,
                        # so if we do have a partial write,
                        # we don't block earlier requests on later ones.
                except OSError as e:
                    # we raise a different exception so that users can distinguish
                    # syscall errors from transport errors
                    raise ConnectionError() from e
            except ConnectionError as e:
                # TODO not necessarily all of the syscalls have failed...
                # some maybe have been actually written, if we had a partial write
                for syscall, coro in reqs_to_write:
                    queue.fill_request(coro, outcome.Error(e))
            else:
                for syscall, coro in reqs_to_write:
                    logger.info("forward_request: %s", syscall)
                    queue.forward_request(self.response_queue, syscall, coro)

    async def _run_responses(self, queue: CoroQueue) -> None:
        buffer = AsyncReadBuffer(self.fromfd)
        while True:
            syscall, coro = await queue.get_one()
            async def read_result() -> int:
                try:
                    async with self.defunct_monitor.throw_on_connection_defunct():
                        return (await buffer.read_struct(SyscallResponse)).value
                except Exception as e:
                    raise SyscallHangup() from e
            result = await outcome.acapture(trio_op, read_result)
            logger.info("fill_request: %s -> %s", syscall, result)
            queue.fill_request(coro, result)
