from rsyscall.handle import Task, Pointer, WrittenPointer, MemoryTransport
from rsyscall.memory.allocator import AllocatorClient, AllocatorInterface
from rsyscall.struct import FixedSize, T_fixed_size, T_has_serializer, T_fixed_serializer, Serializer, Bytes, BytesSerializer

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

    @t.overload
    async def malloc(self, cls: t.Type[bytes]) -> Pointer[bytes]: ...
    @t.overload
    async def malloc(self, cls: t.Type[T_fixed_size]) -> Pointer[T_fixed_size]: ...
    @t.overload
    async def malloc(self, cls: t.Type[T_fixed_serializer], size: int, alignment: int=1) -> Pointer[T_fixed_serializer]: ...

    async def malloc(self, cls: t.Union[t.Type[bytes], t.Type[T_fixed_serializer]],
                     size: int=None, alignment: int=1
    ) -> t.Union[Pointer[bytes], Pointer[T_fixed_serializer]]:
        if size is None:
            return await self.malloc_struct(cls) # type: ignore
        else:
            if issubclass(cls, bytes):
                return await self.malloc_serializer(BytesSerializer(), size, alignment)
            else:
                return await self.malloc_type(cls, size, alignment)

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

    @t.overload
    async def ptr(self, data: t.Union[bytes], alignment: int=1) -> WrittenPointer[bytes]: ...
    @t.overload
    async def ptr(self, data: T_has_serializer, alignment: int=1) -> WrittenPointer[T_has_serializer]: ...
    async def ptr(self, data: t.Union[bytes, T_has_serializer], alignment: int=1
    ) -> t.Union[WrittenPointer[bytes], WrittenPointer[T_has_serializer]]:
        if isinstance(data, bytes):
            return await self.to_pointer(Bytes(data), alignment)
        else:
            return await self.to_pointer(data, alignment)

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
