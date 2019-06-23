import abc
from rsyscall.near.sysif import SyscallInterface, SyscallResponse
from rsyscall.tasks.connection import Syscall, SyscallConnection, ConnectionResponse
from rsyscall.tasks.util import log_syscall, raise_if_error
from rsyscall.handle import FileDescriptor
from dataclasses import dataclass
import logging
import typing as t

@dataclass
class BaseSyscallResponse(SyscallResponse):
    "A pending response to a syscall, which polls for the actual response by repeatedly calling a function"
    process_responses: t.Any
    response: ConnectionResponse

    async def receive(self, logger=None) -> int:
        while self.response.result is None:
            if logger:
                logger.debug("no response yet for %s, calling process responses", self.response)
            await self.process_responses()
            if logger:
                logger.debug("exited process responses for %s", self.response)
        raise_if_error(self.response.result)
        return self.response.result

class BaseSyscallInterface(SyscallInterface):
    """Shared functionality for definining a syscall interface using SyscallConnection

    """
    @abc.abstractmethod
    async def _read_pending_responses(self) -> None:
        "Wait for some responses to come back from the rsyscall server"
        pass

    def __init__(self, rsyscall_connection: SyscallConnection) -> None:
        self.rsyscall_connection = rsyscall_connection

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

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0
    ) -> BaseSyscallResponse:
        "Write syscall request on connection and return a response that will contain its result"
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        conn_response = await self.rsyscall_connection.write_request(Syscall(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6)))
        response = BaseSyscallResponse(self._read_pending_responses, conn_response)
        return response
