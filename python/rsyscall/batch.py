"Batch pointer reading/writing"
from __future__ import annotations
from rsyscall.handle import Task, Pointer, WrittenPointer, AllocationInterface, MemoryMapping, MemoryGateway
import rsyscall.near
import contextlib
import abc
from rsyscall.struct import T_has_serializer, T_fixed_serializer, T_fixed_size, Serializer
import rsyscall.memory.allocator as memory
import rsyscall.base as base
import rsyscall.far as far
import typing as t

T = t.TypeVar('T')
class BatchSemantics:
    def __init__(self, task: Task) -> None:
        self.task = task

    def to_pointer(self, data: T_has_serializer, alignment: int=1) -> WrittenPointer[T_has_serializer]:
        serializer = data.get_self_serializer(self.task)
        data_bytes = serializer.to_bytes(data)
        ptr = self.malloc_serializer(serializer, len(data_bytes))
        try:
            return self.write(ptr, data)
        except:
            ptr.free()
            raise

    def malloc_type(self, cls: t.Type[T_fixed_serializer], size: int) -> Pointer[T_fixed_serializer]:
        return self.malloc_serializer(cls.get_serializer(self.task), size)

    def malloc_struct(self, cls: t.Type[T_fixed_size]) -> Pointer[T_fixed_size]:
        return self.malloc_type(cls, cls.sizeof())

    @abc.abstractmethod
    def malloc_serializer(self, serializer: Serializer[T], n: int, alignment: int=1) -> Pointer[T]: ...
    # we'll do self-reference by passing a function Pointer -> bytes
    # that's a hassle though because we do want write in the full interface.
    @abc.abstractmethod
    def write(self, ptr: Pointer[T], data: T) -> WrittenPointer[T]: ...

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

class NoopGateway(MemoryGateway):
    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        raise Exception("shouldn't try to read")
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        pass
        
class NullSemantics(BatchSemantics):
    def __init__(self, task: Task) -> None:
        super().__init__(task)
        self.allocations: t.List[t.Tuple[int, int]] = []

    def malloc_serializer(self, serializer: Serializer[T], n: int, alignment: int=1) -> Pointer[T]:
        self.allocations.append((n, alignment))
        ptr = Pointer(MemoryMapping(self.task, rsyscall.near.MemoryMapping(0, n, 4096), rsyscall.near.File()),
                      NoopGateway(), serializer, NullAllocation(n))
        return ptr

    def write(self, ptr: Pointer[T], data: T) -> WrittenPointer[T]:
        return ptr._wrote(data)

    @staticmethod
    async def run(task: Task, batch: t.Callable[[BatchSemantics], t.Awaitable[T]]) -> t.List[t.Tuple[int, int]]:
        sem = NullSemantics(task)
        await batch(sem)
        return sem.allocations

class WriteSemantics(BatchSemantics):
    def __init__(self, task: Task, transport: base.MemoryTransport,
                 allocations: t.Sequence[t.Tuple[MemoryMapping, AllocationInterface]]) -> None:
        super().__init__(task)
        self.transport = transport
        self.allocations = list(allocations)
        self.writes: t.List[WrittenPointer] = []

    def malloc_serializer(self, serializer: Serializer[T], n: int, alignment: int=1) -> Pointer[T]:
        mapping, allocation = self.allocations.pop(0)
        if allocation.size() != n:
            raise Exception("batch operation seems to be non-deterministic, ",
                            "allocating different sizes/in different order on second run")
        return Pointer(mapping, self.transport, serializer, allocation)

    def write(self, ptr: Pointer[T], data: T) -> WrittenPointer[T]:
        written = ptr._wrote(data)
        self.writes.append(written)
        return written

    @staticmethod
    async def run(task: Task, transport: base.MemoryTransport,
                  batch: t.Callable[[BatchSemantics], t.Awaitable[T]],
                  allocations: t.Sequence[t.Tuple[MemoryMapping, AllocationInterface]]
    ) -> t.Tuple[T, t.List[WrittenPointer]]:
        sem = WriteSemantics(task, transport, allocations)
        ret = await batch(sem)
        return ret, sem.writes

async def perform_async_batch(
        task: Task,
        transport: base.MemoryTransport,
        allocator: memory.AllocatorInterface,
        batch: t.Callable[[BatchSemantics], t.Awaitable[T]],
) -> T:
    sizes = await NullSemantics.run(task, batch)
    allocations = await allocator.bulk_malloc([(size, alignment) for size, alignment in sizes])
    ret, desired_writes = await WriteSemantics.run(task, transport, batch, allocations)
    await transport.batch_write([(ptr, ptr.serializer.to_bytes(ptr.data))
                                 for ptr in desired_writes])
    return ret

async def perform_batch(
        task: Task,
        transport: base.MemoryTransport,
        allocator: memory.AllocatorInterface,
        batch: t.Callable[[BatchSemantics], T],
) -> T:
    async def abatch(sem: BatchSemantics) -> T:
        return batch(sem)
    return await perform_async_batch(task, transport, allocator, abatch)
