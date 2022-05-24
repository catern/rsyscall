"`#include <sys/mman.h>`"
from __future__ import annotations
from rsyscall._raw import lib # type: ignore
from rsyscall.linux.memfd import MFD
import enum

__all__ = [
    "MFD",
    "PROT",
    "MAP",
    "MappableFileDescriptor",
    "MemoryMappingTask",
    "MemoryMapping",
]

class PROT(enum.IntFlag):
    EXEC = lib.PROT_EXEC
    READ = lib.PROT_READ
    WRITE = lib.PROT_WRITE
    NONE = lib.PROT_NONE

class MAP(enum.IntFlag):
    PRIVATE = lib.MAP_PRIVATE
    SHARED = lib.MAP_SHARED
    ANONYMOUS = lib.MAP_ANONYMOUS
    POPULATE = lib.MAP_POPULATE

class MADV(enum.IntFlag):
    NORMAL = lib.MADV_NORMAL # No further special treatment.
    RANDOM = lib.MADV_RANDOM # Expect random page references.
    SEQUENTIAL = lib.MADV_SEQUENTIAL # Expect sequential page references.
    WILLNEED = lib.MADV_WILLNEED # Will need these pages.
    DONTNEED = lib.MADV_DONTNEED # Don't need these pages.
    FREE = lib.MADV_FREE # Free pages only if memory pressure.
    REMOVE = lib.MADV_REMOVE # Remove these pages and resources.
    DONTFORK = lib.MADV_DONTFORK # Do not inherit across fork.
    DOFORK = lib.MADV_DOFORK # Do inherit across fork.
    MERGEABLE = lib.MADV_MERGEABLE # KSM may merge identical pages.
    UNMERGEABLE = lib.MADV_UNMERGEABLE # KSM may not merge identical pages.
    HUGEPAGE = lib.MADV_HUGEPAGE # Worth backing with hugepages.
    NOHUGEPAGE = lib.MADV_NOHUGEPAGE # Not worth backing with hugepages.
    DONTDUMP = lib.MADV_DONTDUMP # Explicity exclude from the core dump, overrides the coredump filter bits.
    DODUMP = lib.MADV_DODUMP # Clear the MADV_DONTDUMP flag.
    WIPEONFORK = lib.MADV_WIPEONFORK # Zero memory on fork, child only.
    KEEPONFORK = lib.MADV_KEEPONFORK # Undo MADV_WIPEONFORK.
    COLD = lib.MADV_COLD # Deactivate these pages.
    PAGEOUT = lib.MADV_PAGEOUT # Reclaim these pages.
    HWPOISON = lib.MADV_HWPOISON # Poison a page for testing.

#### Classes ####
from dataclasses import dataclass
import rsyscall.far
import rsyscall.near
import rsyscall.near as near
import typing as t

@dataclass(frozen=True)
class MemoryMapping:
    __slots__ = ('task', 'near', 'file')
    task: MemoryMappingTask
    near: rsyscall.near.MemoryMapping
    file: rsyscall.far.File

    async def munmap(self) -> None:
        await _munmap(self.task.sysif, self.near)

    async def madvise(self, advice: MADV) -> None:
        await _madvise(self.task.sysif, self.near, advice)

    def for_task(self, task: MemoryMappingTask) -> MemoryMapping:
        if task.address_space != self.task.address_space:
            raise rsyscall.far.AddressSpaceMismatchError()
        return MemoryMapping(task, self.near, self.file)

    def __str__(self) -> str:
        return f"MemoryMapping({str(self.task)}, {str(self.near)})"

    def __repr__(self) -> str:
        return str(self)

from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask

class MemoryMappingTask(FileDescriptorTask):
    async def mmap(self, length: int, prot: PROT, flags: MAP,
                   page_size: int=4096,
    ) -> MemoryMapping:
        # a mapping without a file descriptor, is an anonymous mapping
        flags |= MAP.ANONYMOUS
        ret = await _mmap(self.sysif, length, prot, flags, page_size=page_size)
        return MemoryMapping(self, ret, rsyscall.far.File())

class MappableFileDescriptor(BaseFileDescriptor):
    task: MemoryMappingTask

    async def mmap(self, length: int, prot: PROT, flags: MAP,
                   offset: int=0,
                   page_size: int=4096,
                   file: rsyscall.far.File=None,
    ) -> MemoryMapping:
        self._validate()
        if file is None:
            file = rsyscall.far.File()
        ret = await _mmap(self.task.sysif, length, prot, flags, fd=self.near, offset=offset, page_size=page_size)
        return MemoryMapping(self.task, ret, file)

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _mmap(sysif: SyscallInterface, length: int, prot: PROT, flags: MAP,
               addr: t.Optional[near.Address]=None,
               fd: t.Optional[near.FileDescriptor]=None, offset: int=0,
               page_size: int=4096) -> near.MemoryMapping:
    if addr is None:
        addr = 0 # type: ignore
    else:
        assert (int(addr) % page_size) == 0
    if fd is None:
        fd = -1 # type: ignore
    # TODO we want Linux to enforce this for us, but instead it just rounds,
    # leaving us unable to later munmap.
    assert (int(length) % page_size) == 0
    ret = await sysif.syscall(SYS.mmap, addr, length, prot, flags, fd, offset)
    return near.MemoryMapping(address=ret, length=length, page_size=page_size)

async def _munmap(sysif: SyscallInterface, mapping: near.MemoryMapping) -> None:
    await sysif.syscall(SYS.munmap, mapping.address, mapping.length)

async def _madvise(sysif: SyscallInterface, mapping: near.MemoryMapping, advice: MADV) -> None:
    await sysif.syscall(SYS.madvise, mapping.address, mapping.length, advice)
