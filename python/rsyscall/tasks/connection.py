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
                 tofd: AsyncFileDescriptor,
                 fromfd: AsyncFileDescriptor,
                 server_infd: FileDescriptor,
                 server_outfd: FileDescriptor,
    ) -> None:
        self.logger = logger
        self.tofd = tofd
        self.fromfd = fromfd
        self.server_infd = server_infd
        self.server_outfd = server_outfd
        self.valid: t.Optional[Pointer[bytes]] = None
        self.request_queue = RequestQueue[RsyscallSyscall, int]()
        reset(self._run_requests())
        self.response_queue = RequestQueue[RsyscallSyscall, int]()
        reset(self._run_responses())

    def get_activity_fd(self) -> FileDescriptor:
        """Return an fd which is readable when there's other syscalls waiting to be done

        This is true by definition: this fd is read by the rsyscall server to receive
        syscalls, and when this fd is readable, it means there's syscalls to be read.

        """
        return self.server_infd

    async def close_interface(self) -> None:
        """Close this SyscallConnection; pending requests will throw SyscallHangup

        We don't close server_infd and server_outfd, because we don't have any way to close
        them; they were handles that used this syscall interface, so now they're broken.

        """
        await self.tofd.handle.shutdown(SHUT.RDWR)
        await self.fromfd.handle.shutdown(SHUT.RDWR)

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
            # wait until we have a batch to do, received from self.pending_requests
            requests = await self.request_queue.get_many()
            self.logger.debug("_run_requests: get_many: %s", requests)
            # write remaining_reqs to memory
            ptr: Pointer[StructList] = await self.tofd.ram.ptr(
                StructList(RsyscallSyscall, [syscall for syscall, coro in requests]))
            self.logger.debug("_run_requests: performed ptr for: %s", requests)
            ptr_to_write, reqs_to_write = ptr, requests
            # TODO write requests to tofd in parallel with receiving more
            # requests from the channel and writing them to memory
            try:
                while ptr_to_write.size() > 0:
                    _, ptr_to_write = await self.tofd.write(ptr_to_write)
                    # TODO mark the requests as complete incrementally,
                    # so if we do have a partial write,
                    # we don't block earlier requests on later ones.
            except OSError as syscall_error:
                exn = SyscallSendError()
                exn.__cause__ = syscall_error
                # TODO not necessarily all of the syscalls have failed...
                # some maybe have been actually written, if we had a partial write
                for syscall, cb in reqs_to_write:
                    cb.throw(exn)
            else:
                for syscall, coro in reqs_to_write:
                    self.logger.debug("forward_request: %s", syscall)
                    self.response_queue.request_cb(syscall, coro)

    async def _run_responses(self) -> None:
        buffer = AsyncReadBuffer(self.fromfd)
        while True:
            syscall, cb = await self.response_queue.get_one()
            self.logger.debug("going to read_result for syscall: %s %s", syscall, self.fromfd.handle.near)
            try:
                value = (await buffer.read_struct(SyscallResponse)).value
            except Exception as exn:
                hangup_exn = SyscallHangup()
                hangup_exn.__cause__ = exn
                cb.throw(hangup_exn)
            else:
                cb.send(value)
