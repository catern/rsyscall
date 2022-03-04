"Our core interfaces for reading/writing memory."
from __future__ import annotations
import typing as t
import abc
import dataclasses
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer, Task

class MemoryTransport:
    "This low-level class allows us to read bytes from memory and write bytes to memory."
    @abc.abstractmethod
    async def read(self, src: Pointer) -> bytes:
        "Read the memory pointed to by this Pointer, and return its contents as a bytestring."
        pass

    @abc.abstractmethod
    async def write(self, dest: Pointer, data: bytes) -> None:
        "Write this bytestring to the memory pointed to by this Pointer."
        pass

@dataclasses.dataclass
class TaskTransport(MemoryTransport):
    task: Task

    async def read(self, src: Pointer) -> bytes:
        return await self.task.sysif.read(src)

    async def write(self, dest: Pointer, data: bytes) -> None:
        return await self.task.sysif.write(dest, data)
