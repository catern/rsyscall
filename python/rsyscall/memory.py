from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.far import AddressSpace, Pointer
from rsyscall.near import SyscallInterface
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.near
import rsyscall.far as far
import rsyscall.handle as handle
import trio
import abc
import enum
import contextlib
import typing as t
import logging
from dataclasses import dataclass
logger = logging.getLogger(__name__)

from rsyscall.sys.mman import ProtFlag, MapFlag

@dataclass
class Allocation(handle.AllocationInterface):
    arena: Arena
    start: int
    end: int
    valid = True

    @property
    def pointer(self) -> Pointer:
        return self.arena.mapping.pointer + self.start

    @property
    def near(self) -> rsyscall.near.Pointer:
        return self.pointer.near

    def free(self) -> None:
        if not self.valid:
            raise Exception("double-free", self.arena, self.start, self.end)
        self.valid = False
        self.arena.allocations.remove(self)

    def size(self) -> int:
        return self.end - self.start

    def split(self, size: int) -> t.Tuple[Allocation, Allocation]:
        if not self.valid:
            raise Exception("can't split freed allocation")
        idx = self.arena.allocations.index(self)
        splitpoint = self.start+size
        first = Allocation(self.arena, self.start, splitpoint)
        second = Allocation(self.arena, splitpoint, self.end)
        self.arena.allocations[idx:idx] = [first, second]
        self.free()
        return first, second

    def __enter__(self) -> 'Pointer':
        return self.pointer

    def __exit__(self, *args, **kwargs) -> None:
        self.free()

class AnonymousMapping:
    @classmethod
    async def make(self, task: far.Task, length: int, prot: ProtFlag, flags: MapFlag) -> AnonymousMapping:
        mapping = await far.mmap(task, length, prot, flags|MapFlag.ANONYMOUS)
        return AnonymousMapping(task, mapping)

    @property
    def pointer(self) -> far.Pointer:
        return self.mapping.as_pointer()

    @property
    def length(self) -> int:
        return self.mapping.near.length

    def __init__(self, task: far.Task, mapping: far.MemoryMapping) -> None:
        self.task = task
        self.mapping = mapping
        self.mapped = True

    async def unmap(self) -> None:
        if self.mapped:
            await far.munmap(self.task, self.mapping)
            self.mapped = False

    async def __aenter__(self) -> AnonymousMapping:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.unmap()

class Arena:
    def __init__(self, mapping: AnonymousMapping) -> None:
        self.mapping = mapping
        self.allocations: t.List[Allocation] = []

    def malloc(self, size: int) -> t.Optional[Allocation]:
        newstart = 0
        for i, alloc in enumerate(self.allocations):
            if (newstart+size) <= alloc.start:
                newalloc = Allocation(self, newstart, newstart+size)
                self.allocations.insert(i, newalloc)
                return newalloc
            newstart = alloc.end
        if (newstart+size) <= self.mapping.length:
            newalloc = Allocation(self, newstart, newstart+size)
            self.allocations.append(newalloc)
            return newalloc
        return None

    async def close(self) -> None:
        if self.allocations:
            raise Exception
        await self.mapping.unmap()

def align(num: int, alignment: int) -> int:
    return num + (alignment - (num % alignment))

class AllocatorInterface:
    @contextlib.asynccontextmanager
    async def bulk_malloc(self, sizes: t.List[int]) -> t.AsyncGenerator[t.List[Pointer], None]:
        # A naive bulk allocator
        pointers: t.List[Pointer] = []
        with contextlib.ExitStack() as stack:
            for size in sizes:
                pointers.append(stack.enter_context(await self.malloc(size)))
            yield pointers

    @abc.abstractmethod
    def malloc(self, size: int) -> t.Awaitable[t.ContextManager[Pointer]]: ...

class PreallocatedAllocator(AllocatorInterface):
    def __init__(self, base_pointer: far.Pointer, length: int) -> None:
        self.base_pointer = base_pointer
        self.length = length
        self.index = 0

    async def malloc(self, size: int) -> t.ContextManager[Pointer]:
        if (self.index + size > self.length):
            raise Exception("too much memory allocated")
        ret = self.base_pointer + self.index
        self.index += size
        return contextlib.nullcontext(ret) # type: ignore
        # we don't free the memory

class Allocator:
    """A somewhat-efficient memory allocator.

    Perfect in its foresight, but not so bright.
    """
    def __init__(self, task: far.Task) -> None:
        self.task = task
        self.lock = trio.Lock()
        self.arenas: t.List[Arena] = []

    @contextlib.asynccontextmanager
    async def bulk_malloc(self, sizes: t.List[int]) -> t.AsyncGenerator[t.List[Pointer], None]:
            pointers: t.List[Pointer] = []
            async with contextlib.AsyncExitStack() as stack:
                async with self.lock:
                    size_index = 0
                    for arena in self.arenas:
                        alloc = arena.malloc(sizes[size_index])
                        if alloc:
                            pointers.append(stack.enter_context(alloc))
                            size_index += 1
                            if size_index == len(sizes):
                                # we finished all the allocations, stop allocating
                                break
                    if size_index != len(sizes):
                        # we hit the end of the arena and now need to allocate more for the remaining sizes:
                        rest_sizes = sizes[size_index:]
                        # let's do it in bulk:
                        remaining_size = sum(rest_sizes)
                        mapping = await AnonymousMapping.make(self.task,
                                                              align(remaining_size, 4096), ProtFlag.READ|ProtFlag.WRITE, MapFlag.PRIVATE)
                        arena = Arena(mapping)
                        for size in rest_sizes:
                            alloc = arena.malloc(size)
                            if alloc is None:
                                raise Exception("some kind of internal error caused a freshly created memory arena to return null for an allocation")
                            else:
                                pointers.append(stack.enter_context(alloc))
                yield pointers

    async def malloc(self, size: int) -> Allocation:
        # TODO should coalesce together multiple pending mallocs waiting on the lock
        async with self.lock:
            for arena in self.arenas:
                alloc = arena.malloc(size)
                if alloc:
                    return alloc
            mapping = await AnonymousMapping.make(self.task,
                                                  align(size, 4096), ProtFlag.READ|ProtFlag.WRITE, MapFlag.PRIVATE)
            arena = Arena(mapping)
            self.arenas.append(arena)
            result = arena.malloc(size)
            if result is None:
                raise Exception("some kind of internal error caused a freshly created memory arena to return null for an allocation")
            else:
                return result

    async def close(self) -> None:
        for arena in self.arenas:
            await arena.close()

class AllocatorClient(AllocatorInterface):
    def __init__(self, task: far.Task, allocator: Allocator) -> None:
        self.task = task
        self.allocator = allocator
        if self.task.address_space != self.allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.allocator.task.address_space)

    @staticmethod
    def make_allocator(task: far.Task) -> AllocatorClient:
        return AllocatorClient(task, Allocator(task))

    def inherit(self, task: far.Task) -> AllocatorClient:
        return AllocatorClient(task, self.allocator)

    def bulk_malloc(self, sizes: t.List[int]) -> t.AsyncContextManager[t.List[Pointer]]:
        if self.task.address_space != self.allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.allocator.task.address_space)
        return self.allocator.bulk_malloc(sizes)

    def malloc(self, size: int) -> t.Awaitable[Allocation]:
        if self.task.address_space != self.allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.allocator.task.address_space)
        return self.allocator.malloc(size)
