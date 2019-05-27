from rsyscall.near import SyscallInterface
import rsyscall.near as near
from rsyscall.handle import FileDescriptor
from rsyscall.tasks.fork import SyscallConnection, SyscallResponse
from rsyscall.tasks.connection import Syscall
import logging
import trio
from rsyscall.tasks.util import log_syscall

class NonChildSyscallInterface(SyscallInterface):
    """An rsyscall connection to a task that is not our child.

    For correctness, we should ensure that we'll get HUP/EOF if the task has
    exited and therefore will never respond. This is most easily achieved by
    making sure that the fds keeping the other end of the SyscallConnection
    open, are only held by one task, and so will be closed when the task
    exits. Note, though, that that requires that the task be in an unshared file
    descriptor space.

    """
    def __init__(self, rsyscall_connection: SyscallConnection,
                 # usually the same pid that's inside the namespaces
                 identifier_process: near.Process) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.logger = logging.getLogger(f"rsyscall.SyscallConnection.{identifier_process.id}")

    def store_remote_side_handles(self, infd: FileDescriptor, outfd: FileDescriptor) -> None:
        self.infd = infd
        self.outfd = outfd

    def get_activity_fd(self) -> FileDescriptor:
        return self.infd

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()
        self.infd._invalidate()
        self.outfd._invalidate()

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        conn_response = await self.rsyscall_connection.write_request(Syscall(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6)))
        response = SyscallResponse(self.rsyscall_connection.read_pending_responses, conn_response)
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
