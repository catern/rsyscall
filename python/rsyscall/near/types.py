"""Definitions of namespace-local identifiers.

These namespace-local identifiers are like near pointers, in systems
with segmented memory. They are valid only within a specific segment
(namespace).

"""

from __future__ import annotations
from dataclasses import dataclass

__all__  = [
    "FileDescriptor",
    "WatchDescriptor",
    "Address",
    "MemoryMapping",
    "Process",
    "ProcessGroup",
]

@dataclass(frozen=True)
class FileDescriptor:
    """The integer identifier for a file descriptor taken by many syscalls.

    This is a file descriptor in a specific file descriptor table, but we don't with this
    object know what file descriptor table that is.

    """
    __slots__ = ('number')
    number: int

    def __str__(self) -> str:
        return f"FD({self.number})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.number

@dataclass(frozen=True)
class WatchDescriptor:
    """The integer identifier for an inotify watch descriptor taken by inotify syscalls.

    This is a watch descriptor for a specific inotify instance, but we don't with this
    object know what inotify instance that is.

    """
    number: int

    def __str__(self) -> str:
        return f"WD({self.number})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.number

@dataclass(frozen=True)
class Address:
    """The integer identifier for a virtual memory address as taken by many syscalls.

    This is an address in a specific address space, but we don't with this object know
    what address space that is.

    """
    __slots__ = ('address')
    address: int

    def __add__(self, other: int) -> 'Address':
        return Address(self.address + other)

    def __sub__(self, other: int) -> 'Address':
        return Address(self.address - other)

    def __str__(self) -> str:
        return f"Address({hex(self.address)})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.address

@dataclass(frozen=True)
class MemoryMapping:
    """The integer identifiers for a virtual memory mapping as taken by many syscalls.

    This is a mapping in a specific address space, but we don't with this object know what
    address space that is.

    We require three pieces of information to describe a memory mapping. 
    - Address is the start address of the memory mapping
    - Length is the length in bytes of the memory mapped region

    Page size is unusual, but required for robustness: While the syscalls related to
    memory mappings don't appear to depend on page size, that's an illusion. They seem to
    deal in sizes in terms of bytes, but if you provide a size which is not a multiple of
    the page size, silent failures or misbehaviors will occur. Misbehavior include the
    sizes being rounded up to the page size, including in munmap, thus unmapping more
    memory than expected.

    As long as we ensure that the original length we pass to mmap is a multiple of the
    page size that will be used for the mapping, then we could get by with just storing
    the length and not the page size. However, the memory mapping API allows unmapping
    only part of a mapping, or in general performing operations on only part of a
    mapping. These splits must happen at page boundaries, and therefore to support
    specifying these splits without allowing silent rounding errors, we need to know the
    page size of the mapping.

    This is especially troubling when mmaping files with an unknown page size, such as
    those passed to us from another program. memfd_create or hugetlbfs can be used to
    create files with an unknown page size, which cannot be robust unmapped. At this time,
    we don't know of a way to learn the page size of such a file. One good solution would
    be for mmap to be taught a new MAP_ENFORCE_PAGE_SIZE flag which requires MAP_HUGE_* to
    be passed when mapping files with nonstandard page size. In this way, we could assert
    the page size of the file and protect against attackers sending us files with
    unexpected page sizes.

    """
    __slots__ = ('address', 'length', 'page_size')
    address: int
    length: int
    page_size: int

    def __post_init_(self) -> None:
        if (self.address % self.page_size) != 0:
            raise Exception("the address for this memory-mapping is not page-aligned", self)
        if (self.length % self.page_size) != 0:
            raise Exception("the length for this memory-mapping is not page-aligned", self)

    def as_address(self) -> Address:
        "Return the starting address of this memory mapping."
        return Address(self.address)

    def __str__(self) -> str:
        if self.page_size == 4096:
            return f"MMap({hex(self.address)}, {self.length})"
        else:
            return f"MMap(pgsz={self.page_size}, {hex(self.address)}, {self.length})"

    def __repr__(self) -> str:
        return str(self)

@dataclass(frozen=True)
class Process:
    """The integer identifier for a process taken by many syscalls.

    This is a process in a specific pid namespace, but we don't with this object know what
    pid namespace that is.

    """
    id: int

    def __int__(self) -> int:
        return self.id

    def __str__(self) -> str:
        return f'Process({self.id})'

    def __repr__(self) -> str:
        return str(self)

@dataclass(frozen=True)
class ProcessGroup:
    """The integer identifier for a process group taken by many syscalls.

    This is a process group in a specific pid namespace, but we don't with this object
    know what pid namespace that is.

    """
    id: int

    def __int__(self) -> int:
        return self.id
