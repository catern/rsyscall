from __future__ import annotations
from dataclasses import dataclass
import rsyscall.far
import rsyscall.near
from rsyscall.far import File
from rsyscall.sys.mman import MAP, PROT

@dataclass
class MemoryMapping:
    task: MemoryMappingTask
    near: rsyscall.near.MemoryMapping
    file: File

    async def munmap(self) -> None:
        await rsyscall.near.munmap(self.task.sysif, self.near)

    def for_task(self, task: MemoryMappingTask) -> MemoryMapping:
        if task.address_space != self.task.address_space:
            raise rsyscall.far.AddressSpaceMismatchError()
        return MemoryMapping(task, self.near, self.file)

class MemoryMappingTask(rsyscall.far.Task):
    async def mmap(self, length: int, prot: PROT, flags: MAP,
                   page_size: int=4096,
    ) -> MemoryMapping:
        # a mapping without a file descriptor, is an anonymous mapping
        flags |= MAP.ANONYMOUS
        ret = await rsyscall.near.mmap(self.sysif, length, prot, flags, page_size=page_size)
        return MemoryMapping(self, ret, File())
