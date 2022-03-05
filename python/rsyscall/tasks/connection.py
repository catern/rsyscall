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
from dneio import RequestQueue, reset, is_running_directly_under_trio, Future
from rsyscall.epoller import AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.handle import Pointer, FileDescriptor
from rsyscall.memory.span import to_span
from rsyscall.near.sysif import SyscallHangup, SyscallSendError, SyscallInterface, Syscall, raise_if_error
from rsyscall.struct import Struct, StructList
from rsyscall.sys.socket import SHUT, MSG
from rsyscall.sys.syscall import SYS
import logging
import trio
import typing as t

__all__ = [
    "SyscallConnection",
    "RsyscallSyscall",
    "SyscallResponse",
]

class RsyscallSyscall(Struct, Syscall):
    "The struct representing a syscall request"
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
class Write:
    data: bytes

@dataclass
class Read:
    count: int

@dataclass
class Barrier:
    pass

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

class SyscallConnection(SyscallInterface):
    "A connection to some rsyscall server where we can make syscalls"
    def __init__(self,
                 logger: logging.Logger,
                 fd: AsyncFileDescriptor,
                 server_fd: FileDescriptor,
    ) -> None:
        self.logger = logger
        self.fd = fd
        self.server_fd = server_fd
        self.valid: t.Optional[Pointer[bytes]] = None
        self.request_queue = RequestQueue[t.Union[RsyscallSyscall, Write, Read, Barrier], t.Union[int, bytes, None]]()
        reset(self._run_requests())
        self.response_queue = RequestQueue[t.Union[RsyscallSyscall, Read, Barrier], t.Union[int, bytes, None]]()
        reset(self._run_responses())

    def __str__(self) -> str:
        return f"SyscallConnection({self.fd.handle}, server={self.server_fd})"

    def get_activity_fd(self) -> FileDescriptor:
        """Return an fd which is readable when there's other syscalls waiting to be done

        This is true by definition: this fd is read by the rsyscall server to receive
        syscalls, and when this fd is readable, it means there's syscalls to be read.

        """
        return self.server_fd

    async def close_interface(self) -> None:
        """Close this SyscallConnection; pending requests will throw SyscallHangup

        We don't close server_fd, because we don't have any way to close it;
        it was a handle that used this syscall interface, so now it's broken.

        """
        await self.fd.handle.shutdown(SHUT.RDWR)

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        syscall = RsyscallSyscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        self.logger.debug("%s", syscall)
        try:
            result = await self.do_syscall(syscall)
            raise_if_error(result)
        except OSError as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise OSError(exn.errno, exn.strerror) from None
        except Exception as exn:
            self.logger.debug("%s -/ %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

    async def do_syscall(self, syscall: RsyscallSyscall) -> int:
        """Write a syscall request and perform it.

        """
        # TODO as a hack, so we don't have to figure it out now, we don't allow
        # a syscall request to be cancelled before it's actually made. we could
        # make this work later, and that would reduce some blocking from waitid
        if is_running_directly_under_trio():
            with trio.CancelScope(shield=True):
                # hmm this cancel scope shields the entire thing. unfortunate...
                return t.cast(int, await self.request_queue.request(syscall))
        else:
            return t.cast(int, await self.request_queue.request(syscall))

    async def write_to_fd(self, data: bytes) -> None:
        req = Write(data)
        if is_running_directly_under_trio():
            with trio.CancelScope(shield=True):
                # hmm this cancel scope shields the entire thing. unfortunate...
                await self.request_queue.request(req)
        else:
            await self.request_queue.request(req)

    async def infallible_recv(self, dest: Pointer) -> None:
        received, remaining = await self.server_fd.recv(dest, MSG.WAITALL)
        if remaining.size() != 0:
            raise RuntimeError("somehow got a partial recv with MSG.WAITALL, the syscall server will now be broken")

    async def write(self, dest: Pointer, data: bytes) -> None:
        if dest.size() != len(data):
            raise Exception("mismatched pointer size", dest.size(), "and data size", len(data))
        self.logger.debug("writing to %s, num bytes: %s", dest, len(data))
        reset(self.infallible_recv(to_span(dest)))
        await self.write_to_fd(data)

    async def read_from_fd(self, count: int) -> bytes:
        req = Read(count)
        if is_running_directly_under_trio():
            with trio.CancelScope(shield=True):
                # hmm this cancel scope shields the entire thing. unfortunate...
                return t.cast(bytes, await self.request_queue.request(req))
        else:
            return t.cast(bytes, await self.request_queue.request(req))

    async def infallible_send(self, src: Pointer) -> None:
        sent, remaining = await self.server_fd.send(to_span(src), MSG.NONE)
        if remaining.size() != 0:
            raise RuntimeError("somehow got a partial send, the syscall server will now be broken")

    async def read(self, src: Pointer) -> bytes:
        self.logger.debug("reading from %s", src)
        read_fut = Future.start(self.read_from_fd(src.size()))
        await self.infallible_send(src)
        return await read_fut.get()

    async def barrier(self) -> None:
        await self.request_queue.request(Barrier())

    async def _run_requests(self) -> None:
        while True:
            req, coro = await self.request_queue.get_one()
            self.logger.debug("_run_requests: get_one: %s", req)
            if isinstance(req, RsyscallSyscall):
                syscall = req
                try:
                    await self.fd.send_all_bytes(syscall, MSG.NOSIGNAL)
                except Exception as syscall_error:
                    exn = SyscallSendError()
                    exn.__cause__ = syscall_error
                    coro.throw(exn)
                else:
                    self.logger.debug("forward_request: %s", syscall)
                    self.response_queue.request_cb(syscall, coro)
            elif isinstance(req, Write):
                write = req
                try:
                    await self.fd.send_all_bytes(write.data, MSG.NOSIGNAL)
                except Exception as syscall_error:
                    exn = SyscallSendError()
                    exn.__cause__ = syscall_error
                    coro.throw(exn)
                else:
                    # once we've written the data, our job is done
                    coro.send(None)
            elif isinstance(req, Read):
                read = req
                # forward this read right on to the read coroutine
                self.response_queue.request_cb(read, coro)
            elif isinstance(req, Barrier):
                self.response_queue.request_cb(req, coro)
            else:
                raise RuntimeError("invalid request", req)

    async def _run_responses(self) -> None:
        buffer = AsyncReadBuffer(self.fd)
        while True:
            req, cb = await self.response_queue.get_one()
            if isinstance(req, RsyscallSyscall):
                syscall = req
                self.logger.debug("going to read_result for syscall: %s %s", syscall, self.fd.handle.near)
                try:
                    value = (await buffer.read_struct(SyscallResponse)).value
                except Exception as exn:
                    hangup_exn = SyscallHangup()
                    hangup_exn.__cause__ = exn
                    cb.throw(hangup_exn)
                else:
                    cb.send(value)
            elif isinstance(req, Read):
                read = req
                self.logger.debug("going to read_length for data read of size %s", read.count)
                try:
                    data = await buffer.read_length(read.count)
                except Exception as exn:
                    hangup_exn = SyscallHangup()
                    hangup_exn.__cause__ = exn
                    cb.throw(hangup_exn)
                else:
                    cb.send(data)
            elif isinstance(req, Barrier):
                # We don't do anything - we just make sure this barrier is
                # sequenced relative to all other operations.
                cb.send(None)
            else:
                raise RuntimeError("invalid request", req)
