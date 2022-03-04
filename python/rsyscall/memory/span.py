from dataclasses import dataclass
from rsyscall.memory.allocation_interface import AllocationInterface
from rsyscall.handle import Pointer
import typing as t

@dataclass
class SpanAllocation(AllocationInterface):
    """An allocation which is a subspan of some other allocation, and can be split freely

    This should be built into our allocation system. In fact, it is: This is what split is
    for. But the ownership is tricky: Splitting an allocation consumes it. We aren't
    supposed to take ownership of the pointers passed to us for write/read, so
    we can't naively split the pointers.  Instead, we use to_span, below, to make them use
    SpanAllocation, so we can split them freely without taking ownership.

    We should make it possible to split an allocation without consuming it, or otherwise
    have multiple references to the same allocation, then we can get rid of this.

    """
    alloc: AllocationInterface
    _offset: int
    _size: int

    def __post_init__(self) -> None:
        if self._offset + self._size > self.alloc.size():
            raise Exception("span falls off the end of the underlying allocation",
                            self._offset, self._size, self.alloc.size())

    def offset(self) -> int:
        return self.alloc.offset() + self._offset

    def size(self) -> int:
        return self._size

    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]:
        if size > self.size():
            raise Exception("called split with size", size, "greater than this allocation's total size", self.size())
        return (SpanAllocation(self.alloc, self._offset, size),
                SpanAllocation(self.alloc, self._offset + size, self._size - size))

    def merge(self, other: AllocationInterface) -> AllocationInterface:
        if not isinstance(other, SpanAllocation):
            raise Exception("can only merge SpanAllocation with SpanAllocation, not", other)
        if self.alloc == other.alloc:
            if self._offset + self._size == other._offset:
                return SpanAllocation(self.alloc, self._offset, self._size + other._size)
            else:
                raise Exception("spans are not adjacent")
        else:
            raise Exception("can't merge spans over two different allocations")

    def free(self) -> None:
        pass

def to_span(ptr: Pointer) -> Pointer:
    "Wraps the pointer's allocation in SpanAllocation so it can be split freely"
    return Pointer(
        ptr.mapping,
        ptr.transport,
        ptr.serializer,
        SpanAllocation(ptr.allocation, 0, ptr.allocation.size()),
        ptr.typ)
