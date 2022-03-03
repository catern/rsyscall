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
from dneio import RequestQueue, reset, is_running_directly_under_trio
from rsyscall.epoller import AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.handle import Pointer, FileDescriptor
from rsyscall.near.sysif import SyscallHangup, SyscallSendError, SyscallInterface, Syscall, raise_if_error
from rsyscall.struct import Struct, StructList
from rsyscall.sys.socket import SHUT
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
        self.request_queue = RequestQueue[RsyscallSyscall, int]()
        reset(self._run_requests())
        self.response_queue = RequestQueue[RsyscallSyscall, int]()
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
                return await self.request_queue.request(syscall)
        else:
            return await self.request_queue.request(syscall)

    async def _run_requests(self) -> None:
        while True:
            syscall, coro = await self.request_queue.get_one()
            self.logger.debug("_run_requests: get_one: %s", syscall)
            try:
                await self.fd.write_all_bytes(syscall)
            except Exception as syscall_error:
                exn = SyscallSendError()
                exn.__cause__ = syscall_error
                coro.throw(exn)
            else:
                self.logger.debug("forward_request: %s", syscall)
                self.response_queue.request_cb(syscall, coro)

    async def _run_responses(self) -> None:
        buffer = AsyncReadBuffer(self.fd)
        while True:
            syscall, cb = await self.response_queue.get_one()
            self.logger.debug("going to read_result for syscall: %s %s", syscall, self.fd.handle.near)
            try:
                value = (await buffer.read_struct(SyscallResponse)).value
            except Exception as exn:
                hangup_exn = SyscallHangup()
                hangup_exn.__cause__ = exn
                cb.throw(hangup_exn)
            else:
                cb.send(value)
