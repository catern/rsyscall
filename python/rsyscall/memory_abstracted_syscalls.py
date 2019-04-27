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
import rsyscall.memory as memory
import rsyscall.handle as handle

from rsyscall.struct import bits
from rsyscall.sys.wait import IdType
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


#### miscellaneous ####
async def read(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
               fd: far.FileDescriptor, count: int) -> bytes:
    logger.debug("read(%s, %s)", fd, count)
    with await allocator.malloc(count) as buf_ptr:
        ret = await far.read(task, fd, buf_ptr, count)
        with trio.open_cancel_scope(shield=True):
            return (await read_to_bytes(transport, buf_ptr, ret))

async def write(sysif: SyscallInterface, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                fd: base.FileDescriptor, buf: bytes) -> int:
    async with localize_data(transport, allocator, buf) as (buf_ptr, buf_len):
        return (await raw_syscall.write(sysif, fd, buf_ptr, buf_len))

async def pread(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                fd: far.FileDescriptor, count: int, offset: int) -> bytes:
    logger.debug("pread(%s, %s, %s)", fd, count, offset)
    with await allocator.malloc(count) as buf_ptr:
        ret = await far.pread(task, fd, buf_ptr, count, offset)
        with trio.open_cancel_scope(shield=True):
            return (await read_to_bytes(transport, buf_ptr, ret))

async def recv(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
               fd: far.FileDescriptor, count: int, flags: int) -> bytes:
    logger.debug("recv(%s, %s, %s)", fd, count, flags)
    with await allocator.malloc(count) as buf_ptr:
        ret = await far.recv(task, fd, buf_ptr, count, flags)
        with trio.open_cancel_scope(shield=True):
            return (await read_to_bytes(transport, buf_ptr, ret))

async def memfd_create(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                       name: bytes, flags: int) -> far.FileDescriptor:
    async with localize_data(transport, allocator, name+b"\0") as (name_ptr, _):
        return (await far.memfd_create(task, name_ptr, flags))

siginfo_size = ffi.sizeof('siginfo_t')
async def waitid(sysif: SyscallInterface, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                 id: t.Union[base.Process, base.ProcessGroup, None], options: int) -> bytes:
    logger.debug("waitid(%s, %s)", id, options)
    with await allocator.malloc(siginfo_size) as infop:
        await raw_syscall.waitid(sysif, id, infop, options, None)
        with trio.open_cancel_scope(shield=True):
            data = await read_to_bytes(transport, infop, siginfo_size)
            return data


#### two syscalls returning a pair of integers ####
intpair = struct.Struct("II")

async def read_to_intpair(transport: MemoryTransport, pair_ptr: base.Pointer) -> t.Tuple[int, int]:
    data = await read_to_bytes(transport, pair_ptr, intpair.size)
    a, b = intpair.unpack(data)
    return a, b

async def pipe(sysif: SyscallInterface, transport: MemoryTransport, allocator: memory.AllocatorInterface,
               flags: int) -> t.Tuple[int, int]:
    logger.debug("pipe(%s)", flags)
    with await allocator.malloc(intpair.size) as bufptr:
        await raw_syscall.pipe2(sysif, bufptr, flags)
        with trio.open_cancel_scope(shield=True):
            return (await read_to_intpair(transport, bufptr))

async def socketpair(sysif: SyscallInterface, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                     domain: int, type: int, protocol: int) -> t.Tuple[int, int]:
    logger.debug("socketpair(%s, %s, %s)", domain, type, protocol)
    with await allocator.malloc(intpair.size) as bufptr:
        await raw_syscall.socketpair(sysif, domain, type, protocol, bufptr)
        with trio.open_cancel_scope(shield=True):
            return (await read_to_intpair(transport, bufptr))


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

    def serialize_preallocated(self, real_ptr: base.Pointer, data: bytes) -> SerializedPointer:
        size = len(data)
        ptr = SerializedPointer(size)
        ptr._real_pointer = real_ptr
        self.operations.append(SerializerOperation(ptr, data))
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

pointer = struct.Struct("Q")
def serialize_null_terminated_array(serializer: Serializer, args: t.List[bytes]) -> SerializedPointer:
    arg_ser_ptrs = [serializer.serialize_data(arg+b"\0") for arg in args]
    argv_ser_ptr = serializer.serialize_lambda(
        (len(args) + 1) * pointer.size,
        lambda: b"".join(pointer.pack(int(ser_ptr.pointer.near)) for ser_ptr in arg_ser_ptrs) + pointer.pack(0)
    )
    return argv_ser_ptr

async def execveat(sysif: SyscallInterface, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                   path: Path, argv: t.List[bytes], envp: t.List[bytes], flags: int) -> None:
    logger.debug("execveat(%s, %s, <len(envp): %d>, %s)", path, argv, len(envp), flags)
    serializer = Serializer()
    path_ptr = serializer.serialize_data(path.to_bytes())
    argv_ser_ptr = serialize_null_terminated_array(serializer, argv)
    envp_ser_ptr = serialize_null_terminated_array(serializer, envp)
    async with serializer.with_flushed(transport, allocator):
        try:
            await raw_syscall.execveat(sysif, None, path_ptr.pointer, argv_ser_ptr.pointer, envp_ser_ptr.pointer, flags)
        except FileNotFoundError as e:
            raise FileNotFoundError(e.errno, e.strerror, path) from None

async def sendmsg_fds(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                      fd: far.FileDescriptor, send_fds: t.List[far.FileDescriptor]) -> None:
    serializer = Serializer()
    dummy_data = serializer.serialize_data(b"\0")
    iovec = serializer.serialize_cffi('struct iovec',
                                      lambda: (ffi.cast('void*', int(dummy_data.pointer)), 1))
    cmsg_fds_bytes = array.array('i',
                                 (int(task.to_near_fd(send_fd)) for send_fd in send_fds)).tobytes()
    cmsghdr = serializer.serialize_data(bytes(ffi.buffer(ffi.new(
        'struct cmsghdr*', (ffi.sizeof('struct cmsghdr')+len(cmsg_fds_bytes), socket.SOL_SOCKET, socket.SCM_RIGHTS)))
    ) + cmsg_fds_bytes)
    msghdr = serializer.serialize_cffi(
        'struct msghdr', lambda: (ffi.cast('void*', 0), 0,
                                  ffi.cast('void*', int(iovec.pointer)), 1,
                                  ffi.cast('void*', int(cmsghdr.pointer)), cmsghdr.size, 0))
    async with serializer.with_flushed(transport, allocator):
        await far.sendmsg(task, fd, msghdr.pointer, msghdr.size)

fd_struct = struct.Struct('i')
async def recvmsg_fds(task: far.Task, transport: MemoryTransport, allocator: memory.AllocatorInterface,
                      fd: far.FileDescriptor, num_fds: int) -> t.List[near.FileDescriptor]:
    serializer = Serializer()
    data_buf = serializer.serialize_uninitialized(1)
    iovec = serializer.serialize_cffi(
        'struct iovec', lambda: (ffi.cast('void*', int(data_buf.pointer)), data_buf.size))
    buf_len = fd_struct.size * num_fds
    cmsgbuf = serializer.serialize_uninitialized(ffi.sizeof('struct cmsghdr') + buf_len)
    msghdr = serializer.serialize_cffi(
        'struct msghdr', lambda: (ffi.cast('void*', 0), 0,
                                  ffi.cast('void*', int(iovec.pointer)), 1,
                                  ffi.cast('void*', int(cmsgbuf.pointer)), cmsgbuf.size, 0))
    async with serializer.with_flushed(transport, allocator):
        await far.recvmsg(task, fd, msghdr.pointer, msghdr.size)
        fds_buf = cmsgbuf.pointer + ffi.sizeof('struct cmsghdr')
        # TODO I should really actually look at how many fds I got rather than assume I got all of them
        local_fds_bytes = await transport.read(fds_buf, buf_len)
        received_fds = [near.FileDescriptor(fd) for fd, in fd_struct.iter_unpack(local_fds_bytes)]
        return received_fds
