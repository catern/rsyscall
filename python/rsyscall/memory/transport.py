"Our core interfaces for reading/writing memory."
from __future__ import annotations
import typing as t
import abc
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer, Task

class MemoryGateway:
    "This low-level class allows us to read bytes from memory and write bytes to memory."
    @abc.abstractmethod
    async def read(self, src: Pointer) -> bytes:
        "Read the memory pointed to by this Pointer, and return its contents as a bytestring."
        pass

    @abc.abstractmethod
    async def write(self, dest: Pointer, data: bytes) -> None:
        "Write this bytestring to the memory pointed to by this Pointer."
        pass

class MemoryTransport(MemoryGateway):
    @abc.abstractmethod
    def inherit(self, task: Task) -> MemoryTransport: ...
