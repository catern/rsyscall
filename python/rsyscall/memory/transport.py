"""Our core interfaces for reading/writing memory
"""
from __future__ import annotations
import typing as t
import abc
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer, Task

class MemoryGateway:
    "This low-level class allows us to read bytes from memory and write bytes to memory"
    @abc.abstractmethod
    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        "A batched version of MemoryGateway.read, for efficiency"
        pass

    async def read(self, src: Pointer) -> bytes:
        "Read the memory pointed to by this Pointer, and return its contents as a bytestring"
        [data] = await self.batch_read([src])
        return data

    @abc.abstractmethod
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        "A batched version of MemoryGateway.read, for efficiency"
        pass

    async def write(self, dest: Pointer, data: bytes) -> None:
        "Write this bytestring to the memory pointed to by this Pointer"
        await self.batch_write([(dest, data)])

class MemoryTransport(MemoryGateway):
    @abc.abstractmethod
    def inherit(self, task: Task) -> MemoryTransport: ...
