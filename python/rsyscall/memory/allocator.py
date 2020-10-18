"""Allocators and allocations of memory.

None of this is actually specific to memory; it would be a good project to make the
allocators indifferent to whether they are allocating memory or allocating something else
- sub-ranges of files, for example.

It would also be nice to provide an allocator that can grow its memory mapping when it
needs new space. That would require us to pin allocations when making use of pointers
using them.

"""
from __future__ import annotations
from dneio import RequestQueue, reset
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.far import AddressSpace
from rsyscall.near.sysif import SyscallInterface
import outcome
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.memory.allocation_interface import AllocationInterface, UseAfterFreeError
from rsyscall.handle import Task
import trio
import abc
import enum
import contextlib
import typing as t
import logging
from dataclasses import dataclass
from rsyscall.sys.mman import PROT, MAP, MemoryMapping
logger = logging.getLogger(__name__)

# We set eq=False because two distinct zero-length allocations can be identical in all
# their fields, yet they should not be treated as equal, such as in calls to .index()
@dataclass(eq=False)
class Allocation(AllocationInterface):
    """An allocation from some Arena.

    We have a reference back to our Arena so that we can do free(), split(), and merge().
    When __del__ is called on this allocation, we'll free ourselves out of our Arena.

    See AllocationInterface for more about this interface.

    """
    arena: Arena
    start: int
    end: int
    valid: bool = True

    def offset(self) -> int:
        if not self.valid:
            try:
                idx = self.arena.allocations.index(self)
            except ValueError:
                idx = -1
            raise UseAfterFreeError(
                "This allocation has already been freed; refusing to return its offset for use in pointers",
                self,
                "idx", idx,
                "self.arena.allocations", self.arena.allocations,
            )
        return self.start

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
            raise Exception("allocations are unexpectedly at non-adjacent indices",
                            a_idx, self, id(self), b_idx, other, id(other))
        new = Allocation(self.arena, self.start, other.end, valid=False)
        self.free()
        other.free()
        arena.allocations.insert(a_idx, new)
        new.valid = True
        return new

    def __str__(self) -> str:
        if self.valid:
            return f"Alloc({str(self.arena)}, {self.start}, {self.end})"
        else:
            return f"Alloc(FREED, {str(self.arena)}, {self.start}, {self.end})"

    def __repr__(self) -> str:
        return str(self)

    def __del__(self) -> None:
        # TODO this is actually not going to work, because the Arena stores references to the allocation
        self.free()

class OutOfSpaceError(Exception):
    "Raised by malloc if the allocation request couldn't be satisfied."
    pass

class AllocatorInterface:
    "A memory allocator; raises OutOfSpaceError if there's no more space."
    async def bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.Sequence[t.Tuple[MemoryMapping, AllocationInterface]]:
        # A naive bulk allocator
        return [await self.malloc(size, alignment) for size, alignment in sizes]

    @abc.abstractmethod
    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, AllocationInterface]: ...

    def inherit(self, task: Task) -> AllocatorInterface:
        raise Exception("can't be inherited:", self)

@dataclass(eq=False)
class Arena(AllocatorInterface):
    "A single memory mapping and allocations within it."
    mapping: MemoryMapping
    allocations: t.List[Allocation]

    def __init__(self, mapping: MemoryMapping) -> None:
        self.mapping = mapping
        self.allocations: t.List[Allocation] = []

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, Allocation]:
        return self.mapping, self.allocate(size, alignment)

    def allocate(self, size: int, alignment: int) -> Allocation:
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
        raise OutOfSpaceError()

    async def close(self) -> None:
        if self.allocations:
            raise Exception
        await self.mapping.munmap()

    def __str__(self) -> str:
        if len(self.allocations) < 10:
            allocations = "[" + ",".join(f"({alloc.start}, {alloc.end})" for alloc in self.allocations) + "]"
        else:
            allocations = f"[...{len(self.allocations)}...]"
        return f"Arena({str(self.mapping)}, {allocations})"

    def __repr__(self) -> str:
        return str(self)

def align(num: int, alignment: int) -> int:
    """Return the lowest value greater than `num` that is cleanly divisible by `alignment`.

    When applied to an address, this returns the next address that is aligned to this
    alignment. When applied to a size, this returns a size that is sufficient to produce
    an aligned value no matter what its starting address is.

    """
    # TODO this is ugly, isn't there an easier way to do this?
    # we do it this way so that we don't overallocate when overhang is 0.
    overhang = (num % alignment)
    if overhang > 0:
        return num + (alignment - overhang)
    else:
        return num

class UnlimitedAllocator:
    """An allocator which just calls `mmap` to request more memory when it runs out.

    """
    def __init__(self, task: Task) -> None:
        self.task = task
        self.lock = trio.Lock()
        self.arenas: t.List[Arena] = []
        self.queue = RequestQueue[t.List[t.Tuple[int, int]], t.Sequence[t.Tuple[MemoryMapping, Allocation]]]()
        reset(self._run())

    async def _run(self) -> None:
        "Try to allocate all these requests; if we run out of space, make one big mmap call for the rest."
        # TODO we should coalesce together multiple pending mallocs waiting on the lock
        while True:
            sizes, cb = await self.queue.get_one()
            cb.resume(await outcome.acapture(self._bulk_malloc, sizes))

    async def _bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.Sequence[t.Tuple[MemoryMapping, Allocation]]:
        "Try to allocate all these requests; if we run out of space, make one big mmap call for the rest."
        allocations: t.List[t.Tuple[MemoryMapping, Allocation]] = []
        size_index = 0
        for arena in self.arenas:
            size, alignment = sizes[size_index]
            if alignment > 4096:
                raise Exception("can't handle alignments of more than 4096 bytes", alignment)
            try:
                allocations.append((arena.mapping, arena.allocate(size, alignment)))
            except OutOfSpaceError:
                pass
            else:
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
            mapping = await self.task.mmap(align(remaining_size, 4096), PROT.READ|PROT.WRITE, MAP.SHARED)
            arena = Arena(mapping)
            self.arenas.append(arena)
            for size, alignment in rest_sizes:
                if alignment > 4096:
                    raise Exception("can't handle alignments of more than 4096 bytes", alignment)
                try:
                    allocations.append((arena.mapping, arena.allocate(size, alignment)))
                except OutOfSpaceError:
                    raise Exception("some kind of internal error caused a freshly created memory arena",
                                    " to return null for an allocation, size", size, "alignment", alignment)
        return allocations

    async def bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.Sequence[t.Tuple[MemoryMapping, Allocation]]:
        return await self.queue.request(sizes)

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, Allocation]:
        [ret] = await self.bulk_malloc([(size, alignment)])
        return ret

    async def close(self) -> None:
        "Unmap all the mappings owned by this Allocator."
        for arena in self.arenas:
            await arena.close()

class AllocatorClient(AllocatorInterface):
    """A task-specific allocator, to protect us from getting memory back for the wrong address space.

    We share a single allocator between multiple AllocatorClients; we call inherit to make
    a new AllocatorClient. Before returning an allocation, we switch the memory mapping
    handle to be owned by self.task. This checks that the task's address space and the
    mapping's address space match, and ensures that the ownership for the mapping is
    correct.

    """
    def __init__(self, task: Task, shared_allocator: UnlimitedAllocator) -> None:
        self.task = task
        self.shared_allocator = shared_allocator
        if self.task.address_space != self.shared_allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.shared_allocator.task.address_space)

    @staticmethod
    def make_allocator(task: Task) -> AllocatorClient:
        return AllocatorClient(task, UnlimitedAllocator(task))

    def inherit(self, task: Task) -> AllocatorClient:
        return AllocatorClient(task, self.shared_allocator)

    async def bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.Sequence[t.Tuple[MemoryMapping, AllocationInterface]]:
        seq = await self.shared_allocator.bulk_malloc(sizes)
        return [(mapping.for_task(self.task), alloc) for mapping, alloc in seq]

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, AllocationInterface]:
        [ret] = await self.bulk_malloc([(size, alignment)])
        return ret
