from __future__ import annotations
from rsyscall.handle import Task, Pointer, WrittenPointer, MemoryTransport, AllocationInterface, MemoryMapping, MemoryGateway
from rsyscall.memory.allocator import AllocatorInterface
from rsyscall.struct import FixedSize, T_fixed_size, T_has_serializer, T_fixed_serializer, Serializer, BytesSerializer
import rsyscall.near as near

import typing as t

__all__ = [
    "RAM",
]

T = t.TypeVar('T')
class RAM:
    def __init__(self, 
                 task: Task,
                 transport: MemoryTransport,
                 allocator: AllocatorInterface,
    ) -> None:
        self.task = task
        self.transport = transport
        self.allocator = allocator

    @t.overload
    async def malloc(self, cls: t.Type[T_fixed_size]) -> Pointer[T_fixed_size]: ...
    @t.overload
    async def malloc(self, cls: t.Type[bytes], size: int, alignment: int=1) -> Pointer[bytes]: ...
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
            ptr = await self.malloc(bytes, len(data))
            return await self._write_to_pointer(ptr, data, data)
        else:
            return await self.to_pointer(data, alignment)

    async def _write_to_pointer(self, ptr: Pointer[T], data: T, data_bytes: bytes) -> WrittenPointer[T]:
        try:
            return await ptr.write(data)
        except:
            ptr.free()
            raise

    async def to_pointer(self, data: T_has_serializer, alignment: int=1) -> WrittenPointer[T_has_serializer]:
        serializer = data.get_self_serializer(self.task)
        data_bytes = serializer.to_bytes(data)
        ptr = await self.malloc_serializer(serializer, len(data_bytes), alignment=alignment)
        return await self._write_to_pointer(ptr, data, data_bytes)

    async def perform_batch(self, op: t.Callable[[BatchSemantics], t.Awaitable[T]],
                                  allocator: AllocatorInterface=None,
    ) -> T:
        if allocator is None:
            allocator = self.allocator
        return await perform_batch(self.task, self.transport, allocator, op)

    async def perform_async_batch(self, op: t.Callable[[BatchSemantics], t.Awaitable[T]],
                                  allocator: AllocatorInterface=None,
    ) -> T:
        return await self.perform_batch(op, allocator)

class NullAllocation(AllocationInterface):
    def __init__(self, n: int) -> None:
        self.n = n

    def offset(self) -> int:
        return 0

    def size(self) -> int:
        return self.n

    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]:
        return NullAllocation(self.size() - size), NullAllocation(size)

    def merge(self, other: AllocationInterface) -> AllocationInterface:
        raise Exception("can't merge")

    def free(self) -> None:
        pass

class LaterAllocator(AllocatorInterface):
    def __init__(self) -> None:
        self.allocations: t.List[t.Tuple[int, int]] = []

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, AllocationInterface]:
        self.allocations.append((size, alignment))
        return (
            MemoryMapping(t.cast(Task, None), near.MemoryMapping(0, size, 4096), near.File()),
            NullAllocation(size),
        )

class NoopTransport(MemoryTransport):
    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        raise Exception("shouldn't try to read")
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        pass
    def inherit(self, task: Task) -> NoopTransport:
        raise Exception("shouldn't try to inherit")

class PrefilledAllocator(AllocatorInterface):
    def __init__(self, allocations: t.Sequence[t.Tuple[MemoryMapping, AllocationInterface]]) -> None:
        self.allocations = list(allocations)

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, AllocationInterface]:
        mapping, allocation = self.allocations.pop(0)
        if allocation.size() != size:
            raise Exception("batch operation seems to be non-deterministic, ",
                            "allocating different sizes/in different order on second run")
        return mapping, allocation

class BatchSemantics(RAM):
    pass

class BatchWriteSemantics(BatchSemantics):
    def __init__(self, 
                 task: Task,
                 transport: MemoryTransport,
                 allocator: AllocatorInterface,
    ) -> None:
        self.task = task
        self.transport = transport
        self.allocator = allocator
        self.writes: t.List[t.Tuple[Pointer, bytes]] = []

    async def _write_to_pointer(self, ptr: Pointer[T], data: T, data_bytes: bytes) -> WrittenPointer[T]:
        wptr = ptr._wrote(data)
        self.writes.append((wptr, data_bytes))
        return wptr

async def perform_batch(
        task: Task,
        transport: MemoryTransport,
        allocator: AllocatorInterface,
        batch: t.Callable[[BatchSemantics], t.Awaitable[T]],
) -> T:
    later_allocator = LaterAllocator()
    await batch(BatchSemantics(task, NoopTransport(), later_allocator))
    allocations = await allocator.bulk_malloc(later_allocator.allocations)
    sem = BatchWriteSemantics(task, transport, PrefilledAllocator(allocations))
    ret = await batch(sem)
    await transport.batch_write(sem.writes)
    return ret

class RAMThread:
    def __init__(self, task: Task, ram: RAM) -> None:
        self.task = task
        self.ram = ram
