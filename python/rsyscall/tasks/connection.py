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
from rsyscall.concurrency import SuspendableCoroutine, Future, Promise, make_future
from rsyscall.struct import T_fixed_size, Struct, Int32, StructList
from rsyscall.epoller import AsyncFileDescriptor, AsyncReadBuffer, EOFException
from rsyscall.near.sysif import SyscallHangup
import abc
import contextlib
import math
import typing as t
import trio

__all__ = [
    "SyscallConnection",
    "ConnectionResponse",
    "Syscall",
]

class ConnectionError(SyscallHangup):
    "Something has gone wrong with the rsyscall connection"
    pass

@dataclass
class Syscall(Struct):
    "The struct representing a syscall request"
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

    T = t.TypeVar('T', bound='Syscall')
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
    response_future: Future[Future[int]]
    response_promise: Promise[Future[int]]

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
        self.request_channel, self.pending_requests = trio.open_memory_channel(math.inf)
        self.suspendable_write = SuspendableCoroutine(self._run_write)
        self.response_channel, self.pending_responses = trio.open_memory_channel(math.inf)
        self.suspendable_read = SuspendableCoroutine(self._run_read)
        self.defunct_monitor = defunct_monitor or ConnectionDefunctOnlyOnEOF()

    async def close(self) -> None:
        "Close this SyscallConnection; will throw if there are pending requests"
        if self.pending_requests.statistics().current_buffer_used:
            # TODO we might want to do this, maybe we could cancel these instead?
            # note that we don't check responses - exit, for example, doesn't get a response...
            # TODO maybe we should cancel the response when we detect death of task in the enclosing classes?
            raise Exception("can't close while there are pending requests", self.pending_requests)
        await self.tofd.close()
        await self.fromfd.close()

    async def write_request(self, syscall: Syscall) -> Future:
        """Write a syscall request, returning a Future for the result.

        """
        future, promise = make_future()
        request = ConnectionRequest(syscall, future, promise)
        # TODO as a hack, so we don't have to figure it out now, we don't allow
        # a syscall request to be cancelled before it's actually made. we could
        # make this work later, and that would reduce some blocking from waitid
        with trio.CancelScope(shield=True):
            async with self.suspendable_write.running():
                await self.request_channel.send(request)
                response = await request.response_future.get()
        return response

    async def _run_write(self, susp: SuspendableCoroutine) -> None:
        remaining_reqs: t.List[ConnectionRequest] = []
        while True:
            # wait until we have a batch to do, received from self.pending_requests
            await susp.wait(lambda: add_batch_to_list(remaining_reqs, self.pending_requests))
            # write remaining_reqs to memory
            ptr = await susp.wait(lambda: self.tofd.ram.ptr(
                StructList(Syscall, [req.syscall for req in remaining_reqs])))
            # find the first part of ptr containing uncancelled requests,
            # and return the tuple containing that pointer and those uncancelled requests.
            # Also returns all other uncancelled requests not covered by that pointer.
            to_write, remaining_reqs = find_uncancelled_part(ptr, remaining_reqs)
            # TODO write requests to tofd in parallel with receiving more
            # requests from the channel and writing them to memory
            if to_write:
                (ptr_to_write, reqs_to_write) = to_write
                try:
                    try:
                        while ptr_to_write.size() > 0:
                            _, ptr_to_write = await susp.wait(
                                lambda: self.tofd.write(ptr_to_write))
                            # TODO mark the requests as complete incrementally,
                            # so if we do have a partial write,
                            # we don't block earlier requests on later ones.
                    except OSError as e:
                        # we raise a different exception so that users can distinguish
                        # syscall errors from transport errors
                        raise ConnectionError() from e
                except ConnectionError as e:
                    for req in reqs_to_write:
                        req.response_promise.throw(e)
                else:
                    for req in reqs_to_write:
                        future, promise = make_future()
                        req.response_promise.send(future)
                        self.response_channel.send_nowait((req, promise))

    async def _run_read(self, susp: SuspendableCoroutine) -> None:
        buffer = AsyncReadBuffer(self.fromfd)
        while True:
            req, promise = await susp.wait(lambda: self.pending_responses.receive())
            try:
                while True:
                    async with susp.suspend_if_cancelled():
                        async with self.defunct_monitor.throw_on_connection_defunct():
                            resp = await buffer.read_struct(SyscallResponse)
                            break
            except EOFException:
                promise.throw(SyscallHangup())
            except Exception as e:
                try:
                    raise SyscallHangup() from e
                except Exception as new_e:
                    promise.throw(new_e)
            else:
                promise.send(resp.value)
