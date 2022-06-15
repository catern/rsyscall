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

@dataclass(eq=False)
class ListStart:
    next: Allocation | Finger | ListEnd

    @property
    def valid(self) -> bool:
        return False

    @property
    def end(self) -> int:
        return 0

@dataclass(eq=False)
class ListEnd:
    prev: Allocation | Finger | ListStart
    start: int

    @property
    def valid(self) -> bool:
        return False

@dataclass(eq=False)
class Finger:
    prev: Allocation | ListStart
    next: Allocation | ListEnd

    def alloc_before(self, size: int, alignment: int) -> Allocation:
        start_ptr = align(self.prev.end, alignment)
        end_ptr = start_ptr + size
        if end_ptr > self.next.start:
            raise OutOfSpaceError()
        return Allocation.add_after(start_ptr, end_ptr, self.prev)

    def move_to_after(self, node: Allocation | ListStart) -> None:
        assert not isinstance(node.next, Finger), f"{node}, {self}"
        # remove from old position
        self.prev.next = self.next
        self.next.prev = self.prev
        # insert into new position
        self.next = node.next
        self.prev = node
        self.next.prev = self
        self.prev.next = self

    @property
    def valid(self) -> bool:
        return False

def make_list(size: int) -> tuple[ListStart, Finger, ListEnd]:
    head = ListStart(t.cast(ListEnd, None))
    tail = ListEnd(head, size)
    head.next = tail
    finger = Finger(head, tail)
    finger.prev.next = finger
    finger.next.prev = finger
    return head, finger, tail

# We set eq=False because two distinct zero-length allocations can be identical in all
# their fields, yet they should not be treated as equal, such as in calls to .index()
@dataclass(eq=False)
class Allocation(AllocationInterface):
    """An allocation from some Arena.

    We have a reference back to our Arena so that we can do free(), split(), and merge().
    When __del__ is called on this allocation, we'll free ourselves out of our Arena.

    See AllocationInterface for more about this interface.

    """
    start: int
    end: int
    prev: Allocation | Finger | ListStart
    next: Allocation | Finger | ListEnd
    valid: bool = True

    def offset(self) -> int:
        if not self.valid:
            raise UseAfterFreeError(
                "This allocation has already been freed; refusing to return its offset for use in pointers",
                self,
            )
        return self.start

    def free(self) -> None:
        if self.valid:
            self.valid = False
            self.prev.next = self.next
            self.next.prev = self.prev

    def size(self) -> int:
        return self.end - self.start

    @staticmethod
    def add_after(start: int, end: int,
                  prev: Allocation | Finger | ListStart,
                  valid: bool = True) -> Allocation:
        next = prev.next
        self = Allocation(start, end, prev, next, valid=valid)
        self.prev.next = self
        self.next.prev = self
        return self

    def split(self, size: int) -> t.Tuple[Allocation, Allocation]:
        if not self.valid:
            raise Exception("can't split freed allocation")
        splitpoint = self.start+size
        self.free()
        first = Allocation.add_after(self.start, splitpoint, self.prev, valid=False)
        second = Allocation.add_after(splitpoint, self.end, first, valid=False)
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
        if not self.next is other:
            raise Exception("can't merge an allocation with anything other than its immediate neighbor!")
        if self.end != other.start:
            raise Exception("to merge allocations, our end", self.end, "must equal their start", other.start)
        self.free()
        other.free()
        new = Allocation.add_after(self.start, other.end, self.prev, valid=False)
        new.valid = True
        return new

    def __str__(self) -> str:
        if self.valid:
            return f"Alloc({self.start}, {self.end})"
        else:
            return f"Alloc(FREED, {self.start}, {self.end})"

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
    """A single memory mapping and allocations within it.

    This is a simple bump allocator.

    """
    mapping: MemoryMapping

    def __init__(self, mapping: MemoryMapping) -> None:
        self.mapping = mapping
        self.head, self.finger, self.tail = make_list(self.mapping.near.length)

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, Allocation]:
        return self.mapping, self.finger.alloc_before(size, alignment)

    def allocate(self, size: int, alignment: int) -> Allocation:
        return self.finger.alloc_before(size, alignment)

    async def close(self) -> None:
        if self.head.next is not self.finger or self.finger.next is not self.tail:
            raise Exception
        await self.mapping.munmap()

    def __str__(self) -> str:
        return f"Arena({str(self.mapping)})"

    def __repr__(self) -> str:
        return str(self)

def ceildiv(x: int, y: int) -> int:
    "How many ys are needed to cover all of x?"
    return x // y + int(bool(x % y))

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

class BumpAllocator(AllocatorInterface):
    """A simple bump allocator relying on virtual memory for efficiency

    This allocator is a simple bump allocator, incrementing an allocation pointer through a large
    area of virtual memory as new allocation requests come in. To avoid inefficient memory usage,
    when all the allocations in a page have been freed, we tell the OS to free that page with
    MADV_REMOVE.

    When we reach the end of the virtual memory space, we wrap around back to the start.  Thus we
    must take care to skip over already-in-use space.

    The fraction of space which is allocated goes to 0 as the virtual memory area increases in size.
    Thus allocation is no more expensive than stack allocation.

    The efficiency/fragmentation is bounded by the ratio of the smallest allocation to the page
    size.  The fact that long-used memory tends to be allocated all at once is especially good for
    fragmentation in this allocator, since such memory will essentially always be allocated in the
    same page.

    Missing features:

    - Currently we don't actually MADV_REMOVE pages when their last allocation is removed.

    - Our references aren't weak, so with our current freeing design, allocations are never removed!

    """
    def __init__(self, task: Task) -> None:
        self.task = task
        self.full_mapping: MemoryMapping
        self.start: ListStart
        self.finger: Finger
        self.end: ListEnd

    @classmethod
    async def make(cls, task: Task, size: int) -> BumpAllocator:
        self = cls(task)
        self.full_mapping = await self.task.mmap(size, PROT.READ|PROT.WRITE, MAP.SHARED)
        self.start, self.finger, self.end = make_list(self.full_mapping.near.length)
        return self

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, Allocation]:
        search_start = self.finger.prev
        while True:
            try:
                return self.full_mapping, self.finger.alloc_before(size, alignment)
            except OutOfSpaceError:
                # stop searching if we're back where we started
                if self.finger.next is search_start:
                    raise OutOfSpaceError("we ran out of virtual memory")
                # move the finger forward, wrapping around back to the start if we hit the end
                if isinstance(self.finger.next, ListEnd):
                    self.finger.move_to_after(self.start)
                else:
                    self.finger.move_to_after(self.finger.next)

class AllocatorClient(AllocatorInterface):
    """A task-specific allocator, to protect us from getting memory back for the wrong address space.

    We share a single allocator between multiple AllocatorClients; we call inherit to make
    a new AllocatorClient. Before returning an allocation, we switch the memory mapping
    handle to be owned by self.task. This checks that the task's address space and the
    mapping's address space match, and ensures that the ownership for the mapping is
    correct.

    """
    def __init__(self, task: Task, shared_allocator: BumpAllocator) -> None:
        self.task = task
        self.shared_allocator = shared_allocator
        if self.task.address_space != self.shared_allocator.task.address_space:
            raise Exception("task and allocator are in different address spaces",
                            self.task.address_space, self.shared_allocator.task.address_space)

    @staticmethod
    async def make_allocator(task: Task) -> AllocatorClient:
        return AllocatorClient(task, await BumpAllocator.make(task, 2**32))

    def inherit(self, task: Task) -> AllocatorClient:
        return AllocatorClient(task, self.shared_allocator)

    async def bulk_malloc(self, sizes: t.List[t.Tuple[int, int]]) -> t.Sequence[t.Tuple[MemoryMapping, AllocationInterface]]:
        seq = await self.shared_allocator.bulk_malloc(sizes)
        return [(mapping.for_task(self.task), alloc) for mapping, alloc in seq]

    async def malloc(self, size: int, alignment: int) -> t.Tuple[MemoryMapping, AllocationInterface]:
        [ret] = await self.bulk_malloc([(size, alignment)])
        return ret
