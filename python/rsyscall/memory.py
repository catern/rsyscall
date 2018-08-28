from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.base import AddressSpace, Pointer, SyscallInterface
import rsyscall.raw_syscalls as raw_syscall
import enum
import typing as t

class ProtFlag(enum.IntFlag):
    EXEC = lib.PROT_EXEC
    READ = lib.PROT_READ
    WRITE = lib.PROT_WRITE
    NONE = lib.PROT_NONE

class MapFlag(enum.IntFlag):
    PRIVATE = lib.MAP_PRIVATE
    ANONYMOUS = lib.MAP_ANONYMOUS

class Allocation:
    def __init__(self, arena: Arena) -> None:
        self.arena = arena

    @property
    def pointer(self) -> Pointer:
        return self.arena.mapping.pointer

    def free(self) -> None:
        self.arena.inuse = False

    def __enter__(self) -> 'Pointer':
        return self.pointer

    def __exit__(self, *args, **kwargs) -> None:
        self.free()

class AnonymousMapping:
    @classmethod
    async def make(self, syscall_interface: SyscallInterface, address_space: AddressSpace,
                   length: int, prot: ProtFlag, flags: MapFlag) -> AnonymousMapping:
        address = await raw_syscall.mmap(syscall_interface, length, prot, flags|MapFlag.ANONYMOUS)
        pointer = Pointer(address_space, address)
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
        self.inuse = False

    def malloc(self, size: int) -> t.Optional[Allocation]:
        if self.inuse or self.mapping.length < size:
            return None
        self.inuse = True
        return Allocation(self)

    async def close(self) -> None:
        if self.inuse:
            raise Exception
        await self.mapping.unmap()

def align(num: int, alignment: int) -> int:
    return num + (alignment - (num % alignment))

class Allocator:
    """A not-particularly-efficient memory allocator
    
    Each request gets a entire memory mapping to itself; so, an entire page.
    """
    # OK! Next step: move this into a rsyscall.memory file which is built on rsyscall.base
    # I guess we'll have that kind of layered structure.
    # And we'll make this an interface, I guess. Since we might want to share it, or whatever
    # Then after that we'll add this to the Task.
    # Then we'll finally be able to do memory_abstracted syscalls
    def __init__(self, syscall_interface: SyscallInterface, address_space: AddressSpace) -> None:
        self.syscall_interface = syscall_interface
        self.address_space = address_space
        self.arenas: t.List[Arena] = []

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
