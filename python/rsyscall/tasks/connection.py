from rsyscall._raw import ffi # type: ignore
from dataclasses import dataclass
from rsyscall.handle import Pointer
from rsyscall.concurrency import OneAtATime
from rsyscall.struct import T_struct, Struct, Int32, Bytes, StructList
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.exceptions import RsyscallException, RsyscallHangup
import typing as t
import trio

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
