import abc
import typing as t
from rsyscall.epoller import AsyncFileDescriptor, EpollCenter
from rsyscall.handle import FileDescriptor, WrittenPointer, Task
from rsyscall.memory.ram import RAM
from rsyscall.sys.socket import Address

class Connection:
    def __init__(self,
                 access_task: Task,
                 access_ram: RAM,
                 access_epoller: EpollCenter,
                 access_connection: t.Optional[t.Tuple[WrittenPointer[Address], FileDescriptor]],
                 connecting_ram: RAM,
                 # TODO we need to lock this, and the access_connection also.
                 # they are shared between processes...
                 connecting_connection: t.Tuple[FileDescriptor, FileDescriptor],
    ) -> None:
        self._access_task = access_task
        self._access_ram = access_ram
        self._access_epoller = access_epoller
        self._access_connection = access_connection
        self._connecting_ram = connecting_ram
        self._connecting_connection = connecting_connection

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]: ...

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]: ...
