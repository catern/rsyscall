from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.base import AddressSpace, Pointer, SyscallInterface
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.near
import rsyscall.far
import abc
import enum
import contextlib
import typing as t

class ProtFlag(enum.IntFlag):
    EXEC = lib.PROT_EXEC
    READ = lib.PROT_READ
    WRITE = lib.PROT_WRITE
    NONE = lib.PROT_NONE

class MapFlag(enum.IntFlag):
    PRIVATE = lib.MAP_PRIVATE
    SHARED = lib.MAP_SHARED
    ANONYMOUS = lib.MAP_ANONYMOUS

class Allocation:
    def __init__(self, arena: Arena, start: int, end: int) -> None:
        self.arena = arena
        self.start = start
        self.end = end

    @property
    def pointer(self) -> Pointer:
        return self.arena.mapping.pointer + self.start

    def free(self) -> None:
        self.arena.allocations.remove(self)

    def __enter__(self) -> 'Pointer':
        return self.pointer

    def __exit__(self, *args, **kwargs) -> None:
        self.free()

class AnonymousMapping:
    @classmethod
    async def make(self, syscall_interface: SyscallInterface, address_space: AddressSpace,
                   length: int, prot: ProtFlag, flags: MapFlag) -> AnonymousMapping:
        address = await raw_syscall.mmap(syscall_interface, length, prot, flags|MapFlag.ANONYMOUS)
        pointer = Pointer(address_space, rsyscall.near.Pointer(address))
        return AnonymousMapping(syscall_interface, pointer, length)

    def __init__(self,
                 syscall_interface: SyscallInterface,
                 pointer: Pointer,
                 length: int,
    ) -> None:
        self.syscall_interface = syscall_interface
        self.pointer = pointer
        self.length = length
        self.mapped = True

    async def unmap(self) -> None:
        if self.mapped:
            await raw_syscall.munmap(self.syscall_interface, self.pointer, self.length)
            self.mapped = False

    async def __aenter__(self) -> AnonymousMapping:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.unmap()

class Arena:
    def __init__(self, mapping: AnonymousMapping) -> None:
        self.mapping = mapping
        self.allocations: t.List[Allocation] = []

    def _alloc(self, start: int, end: int) -> Allocation:
        newalloc = Allocation(self, start, end)
        self.allocations.append(newalloc)
        return newalloc

    def malloc(self, size: int) -> t.Optional[Allocation]:
        newstart = 0
        for alloc in self.allocations:
            if (newstart+size) <= alloc.start:
                return self._alloc(newstart, newstart+size)
            newstart = alloc.end
        if (newstart+size) <= self.mapping.length:
            return self._alloc(newstart, newstart+size)
        return None

    async def close(self) -> None:
        if self.allocations:
            raise Exception
        await self.mapping.unmap()

def align(num: int, alignment: int) -> int:
    return num + (alignment - (num % alignment))

class AllocatorInterface:
    async def bulk_malloc(self, sizes: t.List[int]) -> t.AsyncContextManager[t.List[Pointer]]:
        # A naive bulk allocator
        pointers: t.List[Pointer] = []
        with contextlib.ExitStack() as stack:
            for size in sizes:
                pointers.append(stack.enter_context(await self.malloc(size)))
            yield pointers

    @abc.abstractmethod
    async def malloc(self, size: int) -> t.ContextManager[Pointer]:
        pass

class PreallocatedAllocator(AllocatorInterface):
    def __init__(self, base_pointer: far.Pointer, length: int) -> None:
        self.base_pointer = base_pointer
        self.length = length
        self.index = 0

    @contextlib.contextmanager
    async def malloc(self, size: int) -> t.ContextManager[Pointer]:
        if (self.index + size > self.length):
            raise Exception("too much memory allocated")
        ret = self.base_pointer + self.index
        self.index += size
        return contextlib.nullcontext(ret)
        # we don't free the memory

class Allocator(AllocatorInterface):
    """A somewhat-efficient memory allocator.

    Perfect in its foresight, but not so bright.
    """
    def __init__(self, syscall_interface: SyscallInterface, address_space: AddressSpace) -> None:
        self.syscall_interface = syscall_interface
        self.address_space = address_space
        self.arenas: t.List[Arena] = []

    @contextlib.asynccontextmanager
    async def bulk_malloc(self, sizes: t.List[int]) -> t.AsyncGenerator[t.List[Pointer], None]:
        pointers: t.List[Pointer] = []
        async with contextlib.AsyncExitStack() as stack:
            size_index = 0
            for arena in self.arenas:
                alloc = arena.malloc(sizes[size_index])
                if alloc:
                    pointers.append(stack.enter_context(alloc))
                    size_index += 1
                    if size_index == len(sizes):
                        # we finished all the allocations, yield up the pointers and return
                        yield pointers
                        return
            # we hit the end of the arena and now need to allocate more for the remaining sizes:
            rest_sizes = sizes[size_index:]
            # let's do it in bulk:
            remaining_size = sum(rest_sizes)
            mapping = await AnonymousMapping.make(self.syscall_interface, self.address_space,
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
        for arena in self.arenas:
            alloc = arena.malloc(size)
            if alloc:
                return alloc
        mapping = await AnonymousMapping.make(self.syscall_interface, self.address_space,
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
