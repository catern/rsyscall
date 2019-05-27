from rsyscall.tasks.base_sysif import BaseSyscallInterface
from rsyscall.tasks.connection import SyscallConnection
import rsyscall.near as near
import logging

class NonChildSyscallInterface(BaseSyscallInterface):
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
        super().__init__(rsyscall_connection)
        self.logger = logging.getLogger(f"rsyscall.SyscallConnection.{identifier_process.id}")

    async def _read_pending_responses(self) -> None:
        await self.rsyscall_connection.read_pending_responses()
