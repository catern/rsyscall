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

@contextlib.asynccontextmanager
async def localize_data(
        transport: MemoryWriter, allocator: memory.AllocatorInterface, data: bytes
) -> t.AsyncGenerator[t.Tuple[base.Pointer, int], None]:
    data_len = len(data)
    with await allocator.malloc(data_len) as data_ptr:
        await transport.write(data_ptr, data)
        yield data_ptr, data_len

async def read_to_bytes(transport: MemoryReader, data: base.Pointer, count: int) -> bytes:
    return (await transport.read(data, count))


#### execveat, which requires a lot of memory fiddling ####
class SerializedPointer:
    def __init__(self, size: int) -> None:
        self.size = size
        self._real_pointer: t.Optional[base.Pointer] = None

    @property
    def pointer(self) -> base.Pointer:
        if self._real_pointer is None:
            raise Exception("SerializedPointer's pointer was accessed before it was actually allocated")
        else:
            return self._real_pointer

def align_pointer(ptr: base.Pointer, alignment: int) -> base.Pointer:
    misalignment = int(ptr) % alignment
    if misalignment == 0:
        return ptr
    else:
        return ptr + (alignment - misalignment)

@dataclass
class SerializerOperation:
    ptr: SerializedPointer
    data: t.Union[bytes, t.Callable[[], bytes], None]
    alignment: int = 1
    def __post_init__(self) -> None:
        assert self.alignment > 0

    def size_to_allocate(self) -> t.Optional[int]:
        if self.ptr._real_pointer is not None:
            return None
        else:
            return self.ptr.size + (self.alignment-1)

    def supply_allocation(self, ptr: base.Pointer) -> None:
        self.ptr._real_pointer = align_pointer(ptr, self.alignment)

    def data_to_copy(self) -> t.Optional[bytes]:
        if isinstance(self.data, bytes):
            return self.data
        elif callable(self.data):
            data_bytes = self.data()
            if len(data_bytes) != self.ptr.size:
                print(self.data)
                print(data_bytes)
                raise Exception("size provided", self.ptr.size, "doesn't match size of bytes",
                                len(data_bytes))
            return data_bytes
        elif self.data is None:
            return None
        else:
            raise Exception("nonsense value in operations", self.data)

class Serializer:
    def __init__(self) -> None:
        self.operations: t.List[SerializerOperation] = []

    def serialize_data(self, data: bytes) -> SerializedPointer:
        size = len(data)
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, data))
        return ptr

    def serialize_null_terminated_data(self, data: bytes) -> SerializedPointer:
        return self.serialize_data(data + b"\0")

    def serialize_lambda(self, size: int, func: t.Callable[[], bytes], alignment=1) -> SerializedPointer:
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, func, alignment))
        return ptr

    def serialize_cffi(self, typ: str, func: t.Callable[[], t.Any]) -> SerializedPointer:
        size = ffi.sizeof(typ)
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, lambda: bytes(ffi.buffer(ffi.new(typ+"*", func())))))
        return ptr

    def serialize_uninitialized(self, size: int) -> SerializedPointer:
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, None))
        return ptr

    @contextlib.asynccontextmanager
    async def with_flushed(self, transport: MemoryTransport, allocator: memory.AllocatorInterface
    ) -> t.AsyncGenerator[None, None]:
        # some are already allocated, so we skip them
        needs_allocation: t.List[t.Tuple[SerializerOperation, int]] = []
        for op in self.operations:
            size = op.size_to_allocate()
            if size:
                needs_allocation.append((op, size))
        async with allocator.bulk_malloc([size for (op, size) in needs_allocation]) as pointers:
            for ptr, (op, _) in zip(pointers, needs_allocation):
                op.supply_allocation(ptr)
            real_operations: t.List[t.Tuple[base.Pointer, bytes]] = []
            for op in self.operations:
                data = op.data_to_copy()
                if data:
                    real_operations.append((op.ptr.pointer, data))
            # copy all the bytes in bulk
            await transport.batch_write(real_operations)
            yield

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
    def to_pointer(self, data: bytes) -> BatchPointer: ...
    @abc.abstractmethod
    def malloc(self, n: int) -> BatchPointer: ...
    @abc.abstractmethod
    def write(self, ptr: BatchPointer, data: bytes) -> None: ...

T = t.TypeVar('T')
class NullSemantics(BatchSemantics):
    def __init__(self) -> None:
        self.allocations: t.List[int] = []

    def to_pointer(self, data: bytes) -> BatchPointer:
        return self.malloc(len(data))

    def malloc(self, n: int) -> BatchPointer:
        self.allocations.append(n)
        ptr = base.Pointer(None, near.Pointer(0)) # type: ignore
        return BatchPointer(ptr, n)

    def write(self, ptr: BatchPointer, data: bytes) -> None:
        pass

    @staticmethod
    def run(batch: t.Callable[[BatchSemantics], T]) -> t.List[int]:
        sem = NullSemantics()
        batch(sem)
        return sem.allocations

class WriteSemantics(BatchSemantics):
    def __init__(self, allocations: t.List[BatchPointer]) -> None:
        self.allocations = allocations
        self.writes: t.List[t.Tuple[base.Pointer, bytes]] = []

    def to_pointer(self, data: bytes) -> BatchPointer:
        ptr = self.malloc(len(data))
        self.write(ptr, data)
        return ptr

    def malloc(self, n: int) -> BatchPointer:
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
    ptrs = await stack.enter_async_context(allocator.bulk_malloc(sizes))
    allocations = [BatchPointer(ptr, size) for ptr, size in zip(ptrs, sizes)]
    ret, desired_writes = WriteSemantics.run(batch, allocations)
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
