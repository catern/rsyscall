"""Memory transport to a remote address space based on reading/writing file descriptors.

We need to be able to read and write to the address spaces of our
threads. We start with the ability to read and write to the address
space of the local thread; we need to bootstrap that into an ability
to read and write to other address spaces.

We could have taken a dependency on some means of RDMA, or used
process_vm_readv/writev, or used other techniques, but these only work
in certain circumstances and places additional dependencies on
us. Nevertheless, they might be useful optimizations in the future.

Instead, we make sure that whenever we want to read and write to any
address space, we have a file descriptor owned by a task in that
address space, which is connected to a file descriptor owned by a task
in an address space that we already can read and write.

Then, the problem is reduced to copying bytes between memory and the
connection underlying the pair of file descriptors. But that's easy:
We just use the "read" and "write" system calls.

So, to write to memory in some address space B, we write to some
memory in some address space A that we already can access; then call
`write` on A's file descriptor to copy the bytes from memory in A into
the connection; then call `read` on B's file descriptor to copy the
bytes from the connection to memory in B.

To read memory in address space B, we just perform this in reverse; we
call `write` on B's file descriptor, and `read` on A's file descriptor.

"""
from __future__ import annotations
from dataclasses import dataclass
from rsyscall import AsyncFileDescriptor, Pointer, FileDescriptor, Task
from rsyscall.memory.allocation_interface import AllocationInterface
from rsyscall.memory.transport import MemoryTransport
import trio
import typing as t

__all__ = [
    "SocketMemoryTransport",
]

@dataclass
class SpanAllocation(AllocationInterface):
    """An allocation which is a subspan of some other allocation, and can be split freely

    This should be built into our allocation system. In fact, it is: This is what split is
    for. But the ownership is tricky: Splitting an allocation consumes it. We aren't
    supposed to take ownership of the pointers passed to us for write/read, so
    we can't naively split the pointers.  Instead, we use to_span, below, to make them use
    SpanAllocation, so we can split them freely without taking ownership.

    We should make it possible to split an allocation without consuming it, or otherwise
    have multiple references to the same allocation, then we can get rid of this.

    """
    alloc: AllocationInterface
    _offset: int
    _size: int

    def __post_init__(self) -> None:
        if self._offset + self._size > self.alloc.size():
            raise Exception("span falls off the end of the underlying allocation",
                            self._offset, self._size, self.alloc.size())

    def offset(self) -> int:
        return self.alloc.offset() + self._offset

    def size(self) -> int:
        return self._size

    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]:
        if size > self.size():
            raise Exception("called split with size", size, "greater than this allocation's total size", self.size())
        return (SpanAllocation(self.alloc, self._offset, size),
                SpanAllocation(self.alloc, self._offset + size, self._size - size))

    def merge(self, other: AllocationInterface) -> AllocationInterface:
        if not isinstance(other, SpanAllocation):
            raise Exception("can only merge SpanAllocation with SpanAllocation, not", other)
        if self.alloc == other.alloc:
            if self._offset + self._size == other._offset:
                return SpanAllocation(self.alloc, self._offset, self._size + other._size)
            else:
                raise Exception("spans are not adjacent")
        else:
            raise Exception("can't merge spans over two different allocations")

    def free(self) -> None:
        pass

def to_span(ptr: Pointer) -> Pointer:
    "Wraps the pointer's allocation in SpanAllocation so it can be split freely"
    return Pointer(
        ptr.mapping,
        ptr.transport,
        ptr.serializer,
        SpanAllocation(ptr.allocation, 0, ptr.allocation.size()),
        ptr.typ)

@dataclass
class SocketMemoryTransport(MemoryTransport):
    """Read and write bytes from a remote address space, using a connected socketpair

    We use the "ram" inside the "local" AsyncFileDescriptor to access
    pointers in the address space of the "local" fd. We use the
    socketpair to transport memory from the "local" address space to
    the address space of the "remote" fd.

    In this way, we turn a transport for the "local" address space,
    plus the connected socketpair, into a transport for the "remote"
    address space.

    """
    local: AsyncFileDescriptor
    remote: FileDescriptor

    def __post_init__(self) -> None:
        self._write_lock = trio.Lock()
        self._read_lock = trio.Lock()

    def inherit(self, task: Task) -> SocketMemoryTransport:
        return SocketMemoryTransport(self.local, task.make_fd_handle(self.remote))

    async def write(self, dest: Pointer, data: bytes) -> None:
        async with self._write_lock:
            with trio.CancelScope(shield=True):
                if dest.size() != len(data):
                    raise Exception("mismatched pointer size", dest.size(), "and data size", len(data))
                dest = to_span(dest)
                src = await self.local.ram.ptr(data)
                async def write() -> None:
                    await self.local.write_all(src)
                async def read() -> None:
                    rest = dest
                    while rest.size() > 0:
                        read, rest = await self.remote.read(rest)
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(read)
                    nursery.start_soon(write)

    async def read(self, src: Pointer) -> bytes:
        async with self._read_lock:
            with trio.CancelScope(shield=True):
                src = to_span(src)
                dest = await self.local.ram.malloc(bytes, src.size())
                async def write() -> None:
                    rest = src
                    while rest.size() > 0:
                        written, rest = await self.remote.write(rest)
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(write)
                    read: t.Optional[Pointer[bytes]] = None
                    rest = dest
                    while rest.size() > 0:
                        more_read, rest = await self.local.read(rest)
                        if read is None:
                            read = more_read
                        else:
                            read = read.merge(more_read)
                if read is None:
                    return b''
                else:
                    return await read.read()
