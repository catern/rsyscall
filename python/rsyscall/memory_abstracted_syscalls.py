from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import trio
import os
import socket
import rsyscall.raw_syscalls as raw_syscall
from rsyscall.base import SyscallInterface, MemoryTransport, MemoryWriter, MemoryReader
from dataclasses import dataclass
import rsyscall.base as base
import rsyscall.far as far
import rsyscall.near as near
import rsyscall.near
import rsyscall.memory as memory
import rsyscall.handle as handle

from rsyscall.struct import bits
from rsyscall.path import Path

import array
import typing as t
import logging
import struct
import signal
import contextlib
import enum
logger = logging.getLogger(__name__)

# TODO I think we should have these take a MemoryAbstractedTask or something,
# above the base Task,
# instead of separate arguments.
#### execveat, which requires a lot of memory fiddling ####

import abc
@dataclass
class BatchPointer:
    ptr: base.Pointer
    size: int
    @property
    def near(self) -> rsyscall.near.Pointer:
        return self.ptr.near
    def bytesize(self) -> int:
        return self.size

class BatchSemantics:
    @abc.abstractmethod
    def to_pointer(self, data: bytes, alignment: int=1) -> BatchPointer: ...
    @abc.abstractmethod
    def malloc(self, n: int, alignment: int=1) -> BatchPointer: ...
    @abc.abstractmethod
    def write(self, ptr: BatchPointer, data: bytes) -> None: ...

T = t.TypeVar('T')
class NullSemantics(BatchSemantics):
    def __init__(self) -> None:
        self.allocations: t.List[t.Tuple[int, int]] = []

    def to_pointer(self, data: bytes, alignment: int=1) -> BatchPointer:
        return self.malloc(len(data), alignment)

    def malloc(self, n: int, alignment: int=1) -> BatchPointer:
        self.allocations.append((n, alignment))
        ptr = base.Pointer(None, near.Pointer(0)) # type: ignore
        return BatchPointer(ptr, n)

    def write(self, ptr: BatchPointer, data: bytes) -> None:
        pass

    @staticmethod
    def run(batch: t.Callable[[BatchSemantics], T]) -> t.List[t.Tuple[int, int]]:
        sem = NullSemantics()
        batch(sem)
        return sem.allocations

class WriteSemantics(BatchSemantics):
    def __init__(self, allocations: t.List[BatchPointer]) -> None:
        self.allocations = allocations
        self.writes: t.List[t.Tuple[base.Pointer, bytes]] = []

    def to_pointer(self, data: bytes, alignment: int=1) -> BatchPointer:
        ptr = self.malloc(len(data))
        self.write(ptr, data)
        return ptr

    def malloc(self, n: int, alignment: int=1) -> BatchPointer:
        alloc = self.allocations.pop(0)
        if alloc.size != n:
            raise Exception("batch operation seems to be non-deterministic, ",
                            "allocating different sizes/in different order on second run")
        return alloc

    def write(self, ptr: BatchPointer, data: bytes) -> None:
        self.writes.append((ptr.ptr, data))

    @staticmethod
    def run(batch: t.Callable[[BatchSemantics], T], allocations: t.List[BatchPointer]
    ) -> t.Tuple[T, t.List[t.Tuple[base.Pointer, bytes]]]:
        sem = WriteSemantics(allocations)
        ret = batch(sem)
        return ret, sem.writes

async def perform_batch(
        transport: MemoryTransport,
        allocator: memory.AllocatorInterface,
        stack: contextlib.AsyncExitStack,
        batch: t.Callable[[BatchSemantics], T],
) -> T:
    sizes = NullSemantics.run(batch)
    allocations = await allocator.bulk_malloc(sizes)
    ptrs = [BatchPointer(allocation.pointer, size) # type: ignore
            for allocation, (size, alignment) in zip(allocations, sizes)]
    ret, desired_writes = WriteSemantics.run(batch, ptrs)
    await transport.batch_write(desired_writes)
    return ret
