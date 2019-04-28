import typing as t
import abc
from rsyscall.far import Pointer

class MemoryWriter:
    @abc.abstractmethod
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None: ...

    async def write(self, dest: Pointer, data: bytes) -> None:
        await self.batch_write([(dest, data)])

class MemoryReader:
    @abc.abstractmethod
    async def batch_read(self, ops: t.List[t.Tuple[Pointer, int]]) -> t.List[bytes]: ...

    async def read(self, src: Pointer, n: int) -> bytes:
        [data] = await self.batch_read([(src, n)])
        return data

class MemoryGateway(MemoryWriter, MemoryReader):
    pass
