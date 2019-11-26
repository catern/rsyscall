"Defines AllocationInterface."
from __future__ import annotations
import abc
import typing as t

class UseAfterFreeError(Exception):
    pass

class AllocationInterface:
    """Represents an allocation of a range of bytes in some file

    The file is typically mapped into memory. Essentially, this is a single allocation
    returned by malloc; but it's not necessarily tied to memory.

    """
    @abc.abstractmethod
    def offset(self) -> int:
        """Get the offset of this allocation in its memory mapping; throws if this allocation has been invalidated.

        TODO this should return the offset of the allocation

        """
        pass
    @abc.abstractmethod
    def size(self) -> int:
        "Get the size of this allocation."
        pass
    @abc.abstractmethod
    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]:
        """Invalidate this allocation and split it into two adjacent allocations.

        These two allocations can be independently freed, or split again, ad infinitum;
        they can also be merged back together with merge.

        """
        pass
    @abc.abstractmethod
    def merge(self, other: AllocationInterface) -> AllocationInterface:
        """Invalidate these two adjacent allocations and merge them into one; only works if they came from split.

        Call this on the left allocation returned from split, and pass the right allocation.

        Depending on the characteristics of the underlying allocator, this may also work
        for two unrelated allocations rather than just ones that came from split, but you
        certainly shouldn't try.

        """
        pass
    @abc.abstractmethod
    def free(self) -> None:
        "Invalidate this allocation and return its range for re-allocation; also called automatically on __del__."
        pass

