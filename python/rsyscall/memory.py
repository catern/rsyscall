from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.far import AddressSpace, Pointer
from rsyscall.near import SyscallInterface
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.handle import AllocationInterface, MemoryMapping, Task
import trio
import abc
import enum
import contextlib
import typing as t
import logging
from dataclasses import dataclass
from rsyscall.sys.mman import PROT, MAP
logger = logging.getLogger(__name__)


@dataclass
class Allocation(AllocationInterface):
    arena: Arena
    start: int
    end: int
    valid: bool = True

    @property
    def pointer(self) -> Pointer:
        if not self.valid:
            raise Exception("can't get pointer for freed allocation")
        return self.arena.mapping.as_pointer() + self.start

    @property
    def near(self) -> rsyscall.near.Pointer:
        return self.pointer.near

    def free(self) -> None:
        if self.valid:
            self.valid = False
            self.arena.allocations.remove(self)

    def size(self) -> int:
        return self.end - self.start

    def split(self, size: int) -> t.Tuple[Allocation, Allocation]:
        if not self.valid:
            raise Exception("can't split freed allocation")
        idx = self.arena.allocations.index(self)
        splitpoint = self.start+size
        first = Allocation(self.arena, self.start, splitpoint, valid=False)
        second = Allocation(self.arena, splitpoint, self.end, valid=False)
        self.free()
        self.arena.allocations[idx:idx] = [first, second]
        first.valid = True
        second.valid = True
        return first, second

    def merge(self, other: AllocationInterface) -> Allocation:
        if not isinstance(other, Allocation):
            raise Exception("can't merge", type(self), "with", type(other))
        if not self.valid:
            raise Exception("self.merge(other) was called when self is already freed")
        if not other.valid:
            raise Exception("self.merge(other) was called when other is already freed")
        if self.arena != other.arena:
            # in general, merge is only supported if they started out from the same allocation
            raise Exception("merging allocations from two different arenas - not supported!")
        arena = self.arena
        if self.end != other.start:
            raise Exception("to merge allocations, our end", self.end, "must equal their start", other.start)
        a_idx = arena.allocations.index(self)
        b_idx = arena.allocations.index(other)
        if a_idx + 1 != b_idx:
            raise Exception("allocations are unexpected at non-adjacent indices", a_idx, b_idx)
        new = Allocation(self.arena, self.start, other.end, valid=False)
        self.free()
        other.free()
        arena.allocations.insert(a_idx, new)
        new.valid = True
        return new

    def __enter__(self) -> 'Pointer':
        return self.pointer

    def __exit__(self, *args, **kwargs) -> None:
        self.free()

    def __del__(self) -> None:
        self.free()

class AllocatorInterface:
    async def bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.Sequence[AllocationInterface]:
        # A naive bulk allocator
        allocs: t.List[AllocationInterface] = []
        with contextlib.ExitStack() as stack:
            for size, alignment in sizes:
                allocs.append(await self.malloc(size, alignment))
            return allocs

    @abc.abstractmethod
    async def malloc(self, size: int, alignment: int) -> AllocationInterface: ...

class Arena(AllocatorInterface):
    def __init__(self, mapping: MemoryMapping) -> None:
        self.mapping = mapping
        self.allocations: t.List[Allocation] = []

    async def malloc(self, size: int, alignment: int) -> Allocation:
        alloc_opt = self.maybe_malloc(size, alignment)
        if alloc_opt is None:
            raise Exception("out of space!")
        return alloc_opt

    def maybe_malloc(self, size: int, alignment: int) -> t.Optional[Allocation]:
        newstart = 0
        for i, alloc in enumerate(self.allocations):
            if (newstart+size) <= alloc.start:
                newalloc = Allocation(self, newstart, newstart+size)
                self.allocations.insert(i, newalloc)
                return newalloc
            newstart = align(alloc.end, alignment)
        if (newstart+size) <= self.mapping.near.length:
            newalloc = Allocation(self, newstart, newstart+size)
            self.allocations.append(newalloc)
            return newalloc
        return None

    async def close(self) -> None:
        if self.allocations:
            raise Exception
        await self.mapping.munmap()

def align(num: int, alignment: int) -> int:
    # TODO this is ugly, isn't there an easier way to do this?
    # we do it this way so that we don't overallocate when overhang is 0;
    overhang = (num % alignment)
    if overhang > 0:
        return num + (alignment - overhang)
    else:
        return num

class PreallocatedAllocation(AllocationInterface):
    def __init__(self, pointer: Pointer, size: int) -> None:
        self.pointer = pointer
        self._size = size

    @property
    def near(self) -> rsyscall.near.Pointer:
        return self.pointer.near

    def free(self) -> None:
        pass

    def split(self, size: int) -> t.Tuple[PreallocatedAllocation, PreallocatedAllocation]:
        raise Exception("can't split preallocated")

    def merge(self, other: AllocationInterface) -> AllocationInterface:
        raise Exception("can't merge")

    def size(self) -> int:
        return self._size

    def __enter__(self) -> 'Pointer':
        return self.pointer

    def __exit__(self, *args, **kwargs) -> None:
        self.free()

    def __del__(self) -> None:
        self.free()

class PreallocatedAllocator(AllocatorInterface):
    def __init__(self, base_pointer: far.Pointer, length: int) -> None:
        self.base_pointer = base_pointer
        self.length = length
        self.index = 0

    async def malloc(self, size: int, alignment: int) -> PreallocatedAllocation:
        if (self.index + size > self.length):
            raise Exception("too much memory allocated")
        ret = self.base_pointer + self.index
        self.index += size
        return PreallocatedAllocation(ret, size)

class Allocator:
    """A somewhat-efficient memory allocator.

    Perfect in its foresight, but not so bright.
    """
    def __init__(self, task: Task) -> None:
        self.task = task
        self.lock = trio.Lock()
        self.arenas: t.List[Arena] = []

    async def bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.List[Allocation]:
        allocations: t.List[Allocation] = []
        async with self.lock:
            size_index = 0
            for arena in self.arenas:
                size, alignment = sizes[size_index]
                if alignment > 4096:
                    raise Exception("can't handle alignments of more than 4096 bytes", alignment)
                alloc = arena.maybe_malloc(size, alignment)
                if alloc:
                    allocations.append(alloc)
                    size_index += 1
                    if size_index == len(sizes):
                        # we finished all the allocations, stop allocating
                        break
            if size_index != len(sizes):
                # we hit the end of the arena and now need to allocate more for the remaining sizes:
                rest_sizes = sizes[size_index:]
                # let's do it in bulk:
                # TODO this usage of align() overestimates how much memory we need;
                # it's not a big deal though, because most things have alignment=1
                remaining_size = sum([align(size, alignment) for size, alignment in rest_sizes])
                mapping = await self.task.mmap(align(remaining_size, 4096), PROT.READ|PROT.WRITE, MAP.PRIVATE)
                arena = Arena(mapping)
                for size, alignment in rest_sizes:
                    if alignment > 4096:
                        raise Exception("can't handle alignments of more than 4096 bytes", alignment)
                    alloc = arena.maybe_malloc(size, alignment)
                    if alloc is None:
                        raise Exception("some kind of internal error caused a freshly created memory arena",
                                        " to return null for an allocation, size", size, "alignment", alignment)
                    else:
                        allocations.append(alloc)
        return allocations

    async def malloc(self, size: int, alignment: int) -> Allocation:
        if alignment > 4096:
            raise Exception("can't handle alignments of more than 4096 bytes", alignment)
        # TODO should coalesce together multiple pending mallocs waiting on the lock
        async with self.lock:
            for arena in self.arenas:
                alloc = arena.maybe_malloc(size, alignment)
                if alloc:
                    return alloc
            mapping = await self.task.mmap(align(size, 4096), PROT.READ|PROT.WRITE, MAP.PRIVATE)
            arena = Arena(mapping)
            self.arenas.append(arena)
            result = arena.maybe_malloc(size, alignment)
            if result is None:
                raise Exception("some kind of internal error caused a freshly created memory arena to return null for an allocation")
            else:
                return result

    async def close(self) -> None:
        for arena in self.arenas:
            await arena.close()

class AllocatorClient(AllocatorInterface):
    def __init__(self, task: Task, allocator: Allocator) -> None:
        self.task = task
        self.allocator = allocator
        if self.task.address_space != self.allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.allocator.task.address_space)

    @staticmethod
    def make_allocator(task: Task) -> AllocatorClient:
        return AllocatorClient(task, Allocator(task))

    def inherit(self, task: Task) -> AllocatorClient:
        return AllocatorClient(task, self.allocator)

    async def bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.Sequence[AllocationInterface]:
        if self.task.address_space != self.allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.allocator.task.address_space)
        return await self.allocator.bulk_malloc(sizes)

    async def malloc(self, size: int, alignment: int=1) -> Allocation:
        if self.task.address_space != self.allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.allocator.task.address_space)
        return await self.allocator.malloc(size, alignment)
