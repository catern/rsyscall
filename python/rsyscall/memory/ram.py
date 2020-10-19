"The high-level interfaces to memory"
from __future__ import annotations
from dneio import run_all
from rsyscall.handle import Task, Pointer, WrittenPointer
from rsyscall.memory.transport import MemoryTransport, MemoryGateway
from rsyscall.memory.allocation_interface import AllocationInterface
from rsyscall.memory.allocator import AllocatorInterface
from rsyscall.struct import FixedSize, T_fixed_size, HasSerializer, T_has_serializer, FixedSerializer, T_fixed_serializer, Serializer, PathLikeSerializer, T_pathlike, StrSerializer
from rsyscall.sys.mman import MemoryMapping
import functools
import os
import rsyscall.near.types as near
import rsyscall.far as far

import typing as t

__all__ = [
    "RAM",
    "perform_batch",
]

class BytesSerializer(Serializer[bytes]):
    def to_bytes(self, val: bytes) -> bytes:
        return val

    def from_bytes(self, data: bytes) -> bytes:
        return data

T = t.TypeVar('T')
class RAM:
    """Central user-friendly class for accessing memory.

    Future work: An option to allocate "const" pointers, which we
    could cache and reuse each time they're requested. This would be
    useful for small pieces of memory which are very frequently used.

    """
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
    async def malloc(self, cls: t.Type[T_fixed_serializer], size: int) -> Pointer[T_fixed_serializer]: ...
    @t.overload
    async def malloc(self, cls: t.Type[T_pathlike], size: int) -> Pointer[T_pathlike]: ...
    @t.overload
    async def malloc(self, cls: t.Type[str], size: int) -> Pointer[str]: ...
    @t.overload
    async def malloc(self, cls: t.Type[bytes], size: int) -> Pointer[bytes]: ...

    # have to type: ignore because of https://github.com/python/mypy/issues/9420
    async def malloc(self, cls: t.Union[  # type: ignore
            t.Type[T_fixed_size],
            t.Type[T_fixed_serializer],
            t.Type[T_pathlike],
            t.Type[str],
            t.Type[bytes],
    ], size: t.Optional[int]=None,
    ) -> t.Union[
        Pointer[T_fixed_size],
        Pointer[T_fixed_serializer],
        Pointer[T_pathlike],
        Pointer[str],
        Pointer[bytes],
    ]:
        "Allocate a typed space in memory, sized according to the size of the type or an explicit size argument"
        if size is None:
            if not issubclass(cls, FixedSize):
                raise Exception("non-FixedSize cls passed to malloc without specifying size to allocate", cls)
            ptr: Pointer = await self.malloc_serializer(cls.get_serializer(self.task), cls.sizeof(), cls)
            return ptr
        else:
            if issubclass(cls, FixedSize):
                raise Exception("Can't pass a FixedSize cls to malloc and also specify the size argument", cls, size)
            if issubclass(cls, FixedSerializer):
                ptr = await self.malloc_serializer(cls.get_serializer(self.task), size, cls)
                return ptr
            # special-case Path/str/bytes so that they don't have to get wrapped just for rsyscall
            elif issubclass(cls, os.PathLike):
                pathlike_cls = t.cast(t.Type[T_pathlike], cls)
                return await self.malloc_serializer(PathLikeSerializer(pathlike_cls), size, pathlike_cls)
            elif issubclass(cls, str):
                return await self.malloc_serializer(StrSerializer(), size, str)
            elif issubclass(cls, bytes):
                return await self.malloc_serializer(BytesSerializer(), size, bytes)
            else:
                raise Exception("don't know how to find serializer for", cls)


    @t.overload
    async def ptr(self, data: T_has_serializer) -> WrittenPointer[T_has_serializer]: ...
    @t.overload
    async def ptr(self, data: T_pathlike) -> WrittenPointer[T_pathlike]: ...
    @t.overload
    async def ptr(self, data: str) -> WrittenPointer[str]: ...
    @t.overload
    async def ptr(self, data: t.Union[bytes]) -> WrittenPointer[bytes]: ...
    async def ptr(self, data: t.Union[T_has_serializer, T_pathlike, str, bytes],
    ) -> t.Union[
        WrittenPointer[T_has_serializer],
        WrittenPointer[T_pathlike],
        WrittenPointer[str], WrittenPointer[bytes],
    ]:
        "Take some serializable data and return a pointer in memory containing it."
        if isinstance(data, HasSerializer):
            serializer = data.get_self_serializer(self.task)
            data_bytes = serializer.to_bytes(data)
            ptr: Pointer = await self.malloc_serializer(
                serializer, len(data_bytes), type(data))
            return await self._write_to_pointer(ptr, data, data_bytes)
        elif isinstance(data, os.PathLike):
            path_serializer = PathLikeSerializer(type(data))
            data_bytes = path_serializer.to_bytes(data)
            ptr = await self.malloc_serializer(path_serializer, len(data_bytes), type(data))
            return await self._write_to_pointer(ptr, data, data_bytes)
        elif isinstance(data, str):
            str_serializer = StrSerializer()
            data_bytes = str_serializer.to_bytes(data)
            ptr = await self.malloc_serializer(str_serializer, len(data_bytes), type(data))
            return await self._write_to_pointer(ptr, data, data_bytes)
        elif isinstance(data, bytes):
            ptr = await self.malloc(bytes, len(data))
            return await self._write_to_pointer(ptr, data, data)
        else:
            raise Exception("don't know how to serialize data passed to ptr", data)

    async def perform_batch(self, op: t.Callable[[RAM], t.Awaitable[T]],
                                  allocator: AllocatorInterface=None,
    ) -> T:
        """Batches together memory operations performed by a callable.
        
        See the free function of the same name for more documentation.

        """
        if allocator is None:
            allocator = self.allocator
        return await perform_batch(self.task, self.transport, allocator, op)

    async def malloc_serializer(
            self, serializer: Serializer[T], size: int, typ: t.Type[T],
    ) -> Pointer[T]:
        """Allocate a typed space in memory using an explicitly-specified Serializer.

        This is useful only in relatively niche situations.

        """
        mapping, allocation = await self.allocator.malloc(size, alignment=1)
        try:
            return Pointer(mapping, self.transport, serializer, allocation, typ)
        except:
            allocation.free()
            raise

    async def _write_to_pointer(self, ptr: Pointer[T], data: T, data_bytes: bytes) -> WrittenPointer[T]:
        try:
            return await ptr.write(data)
        except:
            ptr.free()
            raise

class NullAllocation(AllocationInterface):
    "An fake allocation for a null pointer."
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
    "An allocator which stores allocation requests and returns null pointers."
    def __init__(self) -> None:
        self.allocations: t.List[t.Tuple[int, int]] = []

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, AllocationInterface]:
        self.allocations.append((size, alignment))
        return (
            MemoryMapping(t.cast(Task, None), near.MemoryMapping(0, size, 4096), far.File()),
            NullAllocation(size),
        )

class NoopTransport(MemoryTransport):
    "A memory transport which doesn't do anything."
    async def read(self, src: Pointer) -> bytes:
        raise Exception("shouldn't try to read")
    async def write(self, dest: Pointer, data: bytes) -> None:
        pass
    def inherit(self, task: Task) -> NoopTransport:
        raise Exception("shouldn't try to inherit")

class PrefilledAllocator(AllocatorInterface):
    "An allocator which has been prefilled with allocations for an exact sequence of calls to malloc."
    def __init__(self, allocations: t.Sequence[t.Tuple[MemoryMapping, AllocationInterface]]) -> None:
        self.allocations = list(allocations)

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, AllocationInterface]:
        mapping, allocation = self.allocations.pop(0)
        if allocation.size() != size:
            raise Exception("batch operation seems to be non-deterministic, ",
                            "allocating different sizes/in different order on second run")
        return mapping, allocation

class BatchWriteSemantics(RAM):
    "A variant of RAM which stores writes to pointers so they can be performed later."
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
        batch: t.Callable[[RAM], t.Awaitable[T]],
) -> T:
    """Batches together memory operations performed by a callable.

    To use, first define a callable which takes a RAM, and produces
    some result using only the methods of the passed-in RAM. There are
    several requirements on this callable, described below. Pass that
    callable to this function, and we'll magically batch its
    operations together and return what it returns.

    Requirements on the callable:
    - Do not have any side-effects other than calling methods on the
      passed-in RAM.
    - Do not branch based on the numeric values of pointers; indeed,
      better that you just don't branch at all.

    Concretely, we'll call the callable twice. Once with a RAM which
    no-ops all the allocations and writes, so that we can know the
    size of all the requested allocations. Then we'll batch-allocate
    all that memory, and call the callable again with a RAM which just
    returns those batch allocations, and no-ops any writes. After that
    second call completes, we batch-perform all the writes, and return
    the result of that second call from this function.
    
    This is useful, among other cases, when performing a lot of memory
    allocation and writes in anticipation of one or more syscalls
    which will read values from that memory. For example, we can batch
    together writing the argv and envp arguments to execve, along with
    all the pointers referenced by them. This is much more efficient.

    This technique is inspired by tagless final style. Unfortunately
    we can't really implement that in Python, so an interface is all
    we've got.

    We had a more explicit style before, where you explicitly listed
    the sizes of the allocations you wanted, but it was far less
    ergonomic and less robust. This style is nominally less efficient
    in CPU time, but it improves robustness by making it not possible
    to mess up in calculating the size you want to allocate.

    """
    later_allocator = LaterAllocator()
    await batch(RAM(task, NoopTransport(), later_allocator))
    allocations = await allocator.bulk_malloc(later_allocator.allocations)
    sem = BatchWriteSemantics(task, transport, PrefilledAllocator(allocations))
    ret = await batch(sem)

    await run_all([functools.partial(transport.write, dest, data)
                   for dest, data in sem.writes])
    return ret
