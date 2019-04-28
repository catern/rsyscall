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
    ptrs = [BatchPointer(allocation.pointer, size)
            for allocation, (size, alignment) in zip(allocations, sizes)]
    ret, desired_writes = WriteSemantics.run(batch, ptrs)
    await transport.batch_write(desired_writes)
    return ret

pointer = struct.Struct("Q")
def write_null_terminated_array(sem: BatchSemantics, args: t.List[bytes]) -> BatchPointer:
    ptrs = [sem.to_pointer(arg+b"\0") for arg in args]
    return sem.to_pointer(b"".join(pointer.pack(int(ptr.near)) for ptr in ptrs) + pointer.pack(0))

async def execveat(sysif: SyscallInterface, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                   path: Path, argv: t.List[bytes], envp: t.List[bytes], flags: int) -> None:
    logger.debug("execveat(%s, %s, <len(envp): %d>, %s)", path, argv, len(envp), flags)
    def op(sem: BatchSemantics) -> t.Tuple[BatchPointer, BatchPointer, BatchPointer]:
        path_ptr = sem.to_pointer(path.to_bytes())
        argv_ptr = write_null_terminated_array(sem, argv)
        envp_ptr = write_null_terminated_array(sem, envp)
        return path_ptr, argv_ptr, envp_ptr
    async with contextlib.AsyncExitStack() as stack:
        (path_ptr, argv_ptr, envp_ptr) = await perform_batch(transport, allocator, stack, op)
        try:
            await raw_syscall.execveat(sysif, None, path_ptr.ptr, argv_ptr.ptr, envp_ptr.ptr, flags)
        except FileNotFoundError as e:
            raise FileNotFoundError(e.errno, e.strerror, path) from None

async def sendmsg_fds(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                      fd: far.FileDescriptor, send_fds: t.List[far.FileDescriptor]) -> None:
    def op(sem: BatchSemantics) -> BatchPointer:
        dummy = sem.to_pointer(b"\0")
        iovec = sem.to_pointer(bytes(ffi.buffer(ffi.new('struct iovec*', (ffi.cast('void*', int(dummy.near)), 1)))))
        cmsg_fds_bytes = array.array('i', (int(task.to_near_fd(send_fd)) for send_fd in send_fds)).tobytes()
        cmsghdr = sem.to_pointer(bytes(ffi.buffer(ffi.new(
            'struct cmsghdr*', (ffi.sizeof('struct cmsghdr')+len(cmsg_fds_bytes), socket.SOL_SOCKET, socket.SCM_RIGHTS)))
        ) + cmsg_fds_bytes)
        msghdr = sem.to_pointer(bytes(ffi.buffer(ffi.new('struct msghdr*', (
            ffi.cast('void*', 0), 0,
            ffi.cast('void*', int(iovec.near)), 1,
            ffi.cast('void*', int(cmsghdr.near)), cmsghdr.size, 0)))))
        return msghdr
    async with contextlib.AsyncExitStack() as stack:
        msghdr = await perform_batch(transport, allocator, stack, op)
        await far.sendmsg(task, fd, msghdr.ptr, msghdr.size)

fd_struct = struct.Struct('i')
async def recvmsg_fds(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                      fd: far.FileDescriptor, num_fds: int) -> t.List[near.FileDescriptor]:
    buf_len = fd_struct.size * num_fds
    def op(sem: BatchSemantics) -> t.Tuple[BatchPointer, BatchPointer]:
        data = sem.malloc(1)
        iovec = sem.to_pointer(bytes(ffi.buffer(ffi.new('struct iovec*', (ffi.cast('void*', int(data.near)), data.size)))))
        cmsghdr = sem.malloc(ffi.sizeof('struct cmsghdr') + buf_len)
        msghdr = sem.to_pointer(bytes(ffi.buffer(ffi.new('struct msghdr*', (
            ffi.cast('void*', 0), 0,
            ffi.cast('void*', int(iovec.near)), 1,
            ffi.cast('void*', int(cmsghdr.near)), cmsghdr.size, 0)))))
        return cmsghdr, msghdr
    async with contextlib.AsyncExitStack() as stack:
        cmsghdr, msghdr = await perform_batch(transport, allocator, stack, op)
        await far.recvmsg(task, fd, msghdr.ptr, msghdr.size)
        fds_buf = cmsghdr.ptr + ffi.sizeof('struct cmsghdr')
        # TODO I should really actually look at how many fds I got rather than assume I got all of them
        local_fds_bytes = await transport.read(fds_buf, buf_len)
        received_fds = [near.FileDescriptor(fd) for fd, in fd_struct.iter_unpack(local_fds_bytes)]
        return received_fds
