import abc
import contextlib
import math
import trio
from rsyscall.concurrency import SuspendableCoroutine, Future, make_future
from rsyscall.near.sysif import SyscallInterface, SyscallResponse
from rsyscall.tasks.connection import Syscall, SyscallConnection
from rsyscall.tasks.util import log_syscall, raise_if_error
from rsyscall.handle import FileDescriptor
from dataclasses import dataclass
import logging
import typing as t

@dataclass
class BaseSyscallResponse(SyscallResponse):
    "A pending response to a syscall, which polls for the actual response by repeatedly calling a function"
    syscall: Syscall
    suspendable: SuspendableCoroutine
    fut: Future[int]

    async def receive(self, logger=None) -> int:
        async with self.suspendable.running():
            val = await self.fut.get()
        if logger:
            logger.debug("%s -> %s", self.syscall, val)
        raise_if_error(val)
        return val

class BaseSyscallInterface(SyscallInterface):
    """Shared functionality for definining a syscall interface using SyscallConnection

    """
    def __init__(self, rsyscall_connection: SyscallConnection) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.suspendable = SuspendableCoroutine(self._run)
        self.response_channel, self.pending_responses = trio.open_memory_channel(math.inf)

    def store_remote_side_handles(self, infd: FileDescriptor, outfd: FileDescriptor) -> None:
        """Store the FD handles that the remote side is using to communicate with us

        We need to track and store these so that we don't close them with garbage
        collection.

        """
        self.infd = infd
        self.outfd = outfd

    def get_activity_fd(self) -> FileDescriptor:
        """Return an fd which is readable when there's other syscalls waiting to be done

        This is true by definition: this fd is read by the rsyscall server to receive
        syscalls, and when this fd is readable, it means there's syscalls to be read.

        """
        return self.infd

    async def close_interface(self) -> None:
        """Close this interface

        We don't immediately close infd and outfd because...  TODO why did we do this.

        """
        await self.rsyscall_connection.close()
        self.infd._invalidate()
        self.outfd._invalidate()

    @contextlib.asynccontextmanager
    async def _throw_on_conn_error(self) -> t.AsyncGenerator[None, None]:
        yield

    async def _run(self, susp: SuspendableCoroutine) -> None:
        while True:
            promise, fut = await susp.wait(lambda: self.pending_responses.receive())
            try:
                while True:
                    async with susp.suspend_if_cancelled():
                        async with self._throw_on_conn_error():
                            async with self.rsyscall_connection.suspendable_read.running():
                                ret = await fut.get()
                                break
            except Exception as e:
                promise.throw(e)
            else:
                promise.send(ret)

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0
    ) -> BaseSyscallResponse:
        "Write syscall request on connection and return a response that will contain its result"
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        syscall = Syscall(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        response_future = await self.rsyscall_connection.write_request(syscall)
        self.response_channel.send_nowait((promise, conn_response_future))
        response = BaseSyscallResponse(syscall, self.suspendable, response_future)
        return response
