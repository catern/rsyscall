"Batch pointer reading/writing"
from __future__ import annotations
from rsyscall.handle import Task, Pointer, WrittenPointer, AllocationInterface
import rsyscall.near
import contextlib
import abc
from rsyscall.struct import T_has_serializer, Serializer
import rsyscall.memory as memory
import rsyscall.base as base
import typing as t

T = t.TypeVar('T')
class BatchSemantics:
    def __init__(self, task: Task) -> None:
        self.task = task

    def to_pointer(self, data: T_has_serializer, alignment: int=1) -> WrittenPointer[T_has_serializer]:
        serializer = data.get_serializer(self.task)
        data_bytes = serializer.to_bytes(data)
        ptr = self.malloc_serializer(serializer, len(data_bytes))
        try:
            return self.write(ptr, data)
        except:
            ptr.free()
            raise

    @abc.abstractmethod
    def malloc_serializer(self, serializer: Serializer[T], n: int, alignment: int=1) -> Pointer[T]: ...
    # we'll do self-reference by passing a function Pointer -> bytes
    # that's a hassle though because we do want write in the full interface.
    @abc.abstractmethod
    def write(self, ptr: Pointer[T], data: T) -> WrittenPointer[T]: ...

class NullAllocation(AllocationInterface):
    def __init__(self, n: int) -> None:
        self.n = n

    @property
    def near(self) -> rsyscall.near.Pointer:
        return rsyscall.near.Pointer(0)

    def size(self) -> int:
        return self.n

    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]:
        raise Exception

    def free(self) -> None:
        pass

class NullSemantics(BatchSemantics):
    def __init__(self, task: Task) -> None:
        super().__init__(task)
        self.allocations: t.List[t.Tuple[int, int, Serializer]] = []

    def malloc_serializer(self, serializer: Serializer[T], n: int, alignment: int=1) -> Pointer[T]:
        self.allocations.append((n, alignment, serializer))
        ptr = Pointer(self.task, serializer, NullAllocation(n))
        return ptr

    def write(self, ptr: Pointer[T], data: T) -> WrittenPointer[T]:
        return ptr._wrote(data)

    @staticmethod
    def run(task: Task, batch: t.Callable[[BatchSemantics], T]) -> t.List[t.Tuple[int, int, Serializer]]:
        sem = NullSemantics(task)
        batch(sem)
        return sem.allocations

class WriteSemantics(BatchSemantics):
    def __init__(self, task: Task, allocations: t.List[Pointer]) -> None:
        super().__init__(task)
        self.allocations = allocations
        self.writes: t.List[WrittenPointer] = []

    def malloc_serializer(self, serializer: Serializer[T], n: int, alignment: int=1) -> Pointer[T]:
        ptr = self.allocations.pop(0)
        if ptr.bytesize() != n:
            raise Exception("batch operation seems to be non-deterministic, ",
                            "allocating different sizes/in different order on second run")
        if type(ptr.serializer) != type(serializer):
            raise Exception("batch operation seems to be non-deterministic, ",
                            "allocating different serializers/in different order on second run")
        return ptr

    def write(self, ptr: Pointer[T], data: T) -> WrittenPointer[T]:
        written = ptr._wrote(data)
        self.writes.append(written)
        return written

    @staticmethod
    def run(task: Task, batch: t.Callable[[BatchSemantics], T], allocations: t.List[Pointer]
    ) -> t.Tuple[T, t.List[WrittenPointer]]:
        sem = WriteSemantics(task, allocations)
        ret = batch(sem)
        return ret, sem.writes

async def perform_batch(
        task: Task,
        transport: base.MemoryTransport,
        allocator: memory.AllocatorInterface,
        batch: t.Callable[[BatchSemantics], T],
) -> T:
    sizes = NullSemantics.run(task, batch)
    allocations = await allocator.bulk_malloc([(size, alignment) for size, alignment, _ in sizes])
    ptrs = [Pointer(task, serializer, allocation)
            for (_, _, serializer), allocation in zip(sizes, allocations)]
    ret, desired_writes = WriteSemantics.run(task, batch, ptrs)
    await transport.batch_write([(ptr.far, ptr.serializer.to_bytes(ptr.data))
                                 for ptr in desired_writes])
    return ret
