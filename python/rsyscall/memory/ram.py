from rsyscall.handle import Task, Pointer, WrittenPointer, MemoryTransport
from rsyscall.memory.allocator import AllocatorClient, AllocatorInterface
from rsyscall.struct import T_fixed_size, T_has_serializer, T_fixed_serializer, Serializer

import typing as t
import rsyscall.batch as batch

__all__ = [
    "RAM",
]

T = t.TypeVar('T')
class RAM:
    def __init__(self, 
                 task: Task,
                 transport: MemoryTransport,
                 # need to be able to inherit
                 allocator: AllocatorClient,
    ) -> None:
        self.task = task
        self.transport = transport
        self.allocator = allocator

    async def malloc_struct(self, cls: t.Type[T_fixed_size]) -> Pointer[T_fixed_size]:
        return await self.malloc_type(cls, cls.sizeof())

    async def malloc_type(self, cls: t.Type[T_fixed_serializer], size: int, alignment: int=1) -> Pointer[T_fixed_serializer]:
        return await self.malloc_serializer(cls.get_serializer(self.task), size)

    async def malloc_serializer(self, serializer: Serializer[T], size: int, alignment: int=1) -> Pointer[T]:
        if alignment == 0:
            raise Exception("alignment is", alignment, "did you mess up arguments?")
        mapping, allocation = await self.allocator.malloc(size, alignment=alignment)
        try:
            return Pointer(mapping, self.transport, serializer, allocation)
        except:
            allocation.free()
            raise

    async def to_pointer(self, data: T_has_serializer, alignment: int=1) -> WrittenPointer[T_has_serializer]:
        serializer = data.get_self_serializer(self.task)
        data_bytes = serializer.to_bytes(data)
        ptr = await self.malloc_serializer(serializer, len(data_bytes), alignment=alignment)
        try:
            return await ptr.write(data)
        except:
            ptr.free()
            raise

    async def perform_batch(self, op: t.Callable[[batch.BatchSemantics], T]) -> T:
        return await batch.perform_batch(self.task, self.transport, self.allocator, op)

    async def perform_async_batch(self, op: t.Callable[[batch.BatchSemantics], t.Awaitable[T]],
                                  allocator: AllocatorInterface=None,
    ) -> T:
        if allocator is None:
            allocator = self.allocator
        return await batch.perform_async_batch(self.task, self.transport, allocator, op)

class RAMThread:
    def __init__(self, task: Task, ram: RAM) -> None:
        self.task = task
        self.ram = ram
