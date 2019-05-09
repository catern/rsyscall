from __future__ import annotations
from dataclasses import dataclass, field
from rsyscall.concurrency import OneAtATime
from rsyscall.memory.ram import RAM
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.handle import MemoryTransport
import rsyscall.base as base
import rsyscall.near as near
import rsyscall.handle as handle
import typing as t
import trio

from rsyscall.struct import Bytes
from rsyscall.handle import AllocationInterface, Pointer, IovecList, FileDescriptor
from rsyscall.memory.allocator import AllocatorClient

@dataclass
class ReadOp:
    src: Pointer
    done: t.Optional[bytes] = None

    @property
    def data(self) -> bytes:
        if self.done is None:
            raise Exception("not done yet")
        return self.done

@dataclass
class WriteOp:
    dest: Pointer
    data: bytes
    done: bool = False

    def assert_done(self) -> None:
        if self.done is None:
            raise Exception("not done yet")

@dataclass
class SpanAllocation(AllocationInterface):
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
    return Pointer(
        ptr.mapping,
        ptr.transport,
        ptr.serializer,
        SpanAllocation(ptr.allocation, 0, ptr.allocation.size()))

@dataclass
class MergedAllocation(AllocationInterface):
    allocs: t.List[AllocationInterface]

    def __post_init__(self) -> None:
        if len(self.allocs) == 0:
            return
        cur = self.allocs[0].offset()
        for alloc in self.allocs:
            if alloc.offset() != cur:
                raise Exception("allocation is not contiguous with previous allocation")
            cur += alloc.size()

    def offset(self) -> int:
        if len(self.allocs) == 0:
            return 0
        return self.allocs[0].offset()

    def size(self) -> int:
        return sum(alloc.size() for alloc in self.allocs)

    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]:
        reached = 0
        for i, alloc in enumerate(self.allocs):
            reached += alloc.size()
            if reached >= size:
                break
        else:
            raise Exception("called split with size", size, "greater than this allocation's total size", reached)
        split_idx = i
        first, second = self.allocs[:split_idx], self.allocs[split_idx+1:]
        if reached == size:
            first = first + [self.allocs[split_idx]]
        else:
            overhang = reached - size
            first_part, second_part = alloc.split(alloc.size() - overhang)
            first = first + [first_part]
            second = [second_part] + second
        return MergedAllocation(first), MergedAllocation(second)

    def merge(self, other: AllocationInterface) -> AllocationInterface:
        raise Exception("doesn't support merge")

    def free(self) -> None:
        pass

def merge_adjacent_pointers(ptrs: t.List[Pointer]) -> Pointer:
    return Pointer(
        ptrs[0].mapping,
        ptrs[0].transport,
        ptrs[0].serializer,
        MergedAllocation([ptr.allocation for ptr in ptrs]))

def merge_adjacent_writes(write_ops: t.List[t.Tuple[Pointer, bytes]]) -> t.List[t.Tuple[Pointer, bytes]]:
    "Note that this is only effective inasmuch as the list is sorted."
    if len(write_ops) == 0:
        return []
    write_ops = sorted(write_ops, key=lambda op: int(op[0].near))
    groupings: t.List[t.List[t.Tuple[Pointer, bytes]]] = []
    ops_to_merge = [write_ops[0]]
    for (prev_op, prev_data), (op, data) in zip(write_ops, write_ops[1:]):
        if prev_op.mapping is op.mapping:
            if int(prev_op.near + len(prev_data)) == int(op.near):
                # the current op is adjacent to the previous op, append it to
                # the list of pending ops to merge together.
                ops_to_merge.append((op, data))
                continue
            elif int(prev_op.near + len(prev_data)) > int(op.near):
                raise Exception("pointers passed to memcpy are overlapping!")
        # the current op isn't adjacent to the previous op, so
        # flush the list of ops_to_merge and start a new one.
        groupings.append(ops_to_merge)
        ops_to_merge = [(op, data)]
    groupings.append(ops_to_merge)

    outputs: t.List[t.Tuple[Pointer, bytes]] = []
    for group in groupings:
        merged_data = b''.join([op[1] for op in group])
        merged_ptr = merge_adjacent_pointers([op[0] for op in group])
        outputs.append((merged_ptr, merged_data))
    return outputs

@dataclass
class PrimitiveSocketMemoryTransport(MemoryTransport):
    local: AsyncFileDescriptor
    local_ram: RAM
    remote: FileDescriptor

    def inherit(self, task: handle.Task) -> PrimitiveSocketMemoryTransport:
        return PrimitiveSocketMemoryTransport(self.local, self.local_ram, task.make_fd_handle(self.remote))

    async def write(self, dest: Pointer, data: bytes) -> None:
        dest = to_span(dest)
        src = await self.local_ram.to_pointer(Bytes(data))
        async def write() -> None:
            await self.local.write_handle(src)
        async def read() -> None:
            rest = dest
            while rest.bytesize() > 0:
                read, rest = await self.remote.read(rest)
        async with trio.open_nursery() as nursery:
            nursery.start_soon(read)
            nursery.start_soon(write)

    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        raise Exception("batch write not supported")

    async def read(self, src: Pointer) -> bytes:
        src = to_span(src)
        dest = await self.local_ram.malloc_type(Bytes, src.bytesize())
        async def write() -> None:
            rest = src
            while rest.bytesize() > 0:
                written, rest = await self.remote.write(rest)
        async with trio.open_nursery() as nursery:
            nursery.start_soon(write)
            read: t.Optional[Pointer[Bytes]] = None
            rest = dest
            while rest.bytesize() > 0:
                more_read, rest = await self.local.read_handle(rest)
                if read is None:
                    read = more_read
                else:
                    read = read.merge(more_read)
        if read is None:
            return b''
        else:
            return await read.read()

    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        raise Exception("batch read not supported")

class SocketMemoryTransport(MemoryTransport):
    """This class wraps a pair of connected file descriptors, one of which is in the local address space.

    The task owning the "local" file descriptor is guaranteed to be in the local address space. This
    means Python runtime memory, such as bytes objects, can be written to it without fear.  The
    "remote" file descriptor is somewhere else - possibly in the same task, possibly on some other
    system halfway across the planet.

    This pair can be used through the helper methods on this class, or borrowed for direct use. When
    directly used, care must be taken to ensure that at the end of use, the buffer between the pair
    is empty; otherwise later users will get that stray leftover data when they try to use it.

    """
    def __init__(self,
                 local: AsyncFileDescriptor,
                 local_ram: RAM,
                 remote: FileDescriptor,
                 remote_allocator: AllocatorClient,
    ) -> None:
        self.local = local
        self.local_ram = local_ram
        self.remote = remote
        self.remote_allocator = remote_allocator
        self.primitive = PrimitiveSocketMemoryTransport(local, local_ram, remote)
        self.primitive_remote_ram = RAM(self.remote.task, self.primitive, self.remote_allocator)
        self.pending_writes: t.List[WriteOp] = []
        self.running_write = OneAtATime()
        self.pending_reads: t.List[ReadOp] = []
        self.running_read = OneAtATime()

    @staticmethod
    def merge_adjacent_reads(read_ops: t.List[ReadOp]) -> t.List[t.Tuple[ReadOp, t.List[ReadOp]]]:
        "Note that this is only effective inasmuch as the list is sorted."
        # also note that this is not really useful
        if len(read_ops) == 0:
            return []
        read_ops = sorted(read_ops, key=lambda op: int(op.src.near))

        groupings: t.List[t.List[ReadOp]] = []
        ops_to_merge = [read_ops[0]]
        for prev_op, op in zip(read_ops, read_ops[1:]):
            if int(prev_op.src.near + prev_op.src.bytesize()) == int(op.src.near):
                # the current op is adjacent to the previous op, append it to
                # the list of pending ops to merge together.
                ops_to_merge.append(op)
            elif int(prev_op.src.near + prev_op.src.bytesize()) > int(op.src.near):
                raise Exception("pointers passed to memcpy are overlapping!")
            else:
                # the current op isn't adjacent to the previous op, so
                # flush the list of ops_to_merge and start a new one.
                groupings.append(ops_to_merge)
                ops_to_merge = [op]
        groupings.append(ops_to_merge)
        outputs: t.List[t.Tuple[ReadOp, t.List[ReadOp]]] = []
        for group in groupings:
            merged_ptr = merge_adjacent_pointers([op.src for op in group])
            outputs.append((ReadOp(merged_ptr), group))
        return outputs

    def inherit(self, task: handle.Task) -> SocketMemoryTransport:
        return SocketMemoryTransport(self.local, self.local_ram, task.make_fd_handle(self.remote),
                                     self.remote_allocator.inherit(task))

    async def _unlocked_batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        ops = sorted(ops, key=lambda op: int(op[0].near))
        ops = merge_adjacent_writes(ops)
        if len(ops) <= 1:
            [(dest, data)] = ops
            await self.primitive.write(dest, data)
        else:
            iovp = await self.primitive_remote_ram.to_pointer(IovecList([ptr for ptr, _ in ops]))
            datap = await self.local_ram.to_pointer(Bytes(b"".join([data for _, data in ops])))
            async with trio.open_nursery() as nursery:
                @nursery.start_soon
                async def write() -> None:
                    await self.local.write_handle(datap)
                rest = iovp
                while rest.bytesize() > 0:
                    _, split, rest = await self.remote.readv(rest)
                    if split:
                        _, split_rest = split
                        while split_rest.bytesize() > 0:
                            _, split_rest = await self.remote.read(split_rest)

    def _start_single_write(self, dest: Pointer, data: bytes) -> WriteOp:
        write = WriteOp(dest, data)
        self.pending_writes.append(write)
        return write

    async def _do_writes(self) -> None:
        async with self.running_write.needs_run() as needs_run:
            if needs_run:
                writes = self.pending_writes
                self.pending_writes = []
                if len(writes) == 0:
                    return
                # TODO we should not use a cancel scope shield, we should use the SyscallResponse API
                with trio.CancelScope(shield=True):
                    await self._unlocked_batch_write([(write.dest, write.data) for write in writes])
                for write in writes:
                    write.done = True

    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        write_ops = [self._start_single_write(dest, data) for (dest, data) in ops]
        await self._do_writes()
        for op in write_ops:
            op.assert_done()

    async def _unlocked_batch_read(self, ops: t.List[ReadOp]) -> None:
        for op in ops:
            op.done = await self.primitive.read(op.src)

    def _start_single_read(self, dest: Pointer) -> ReadOp:
        op = ReadOp(dest)
        self.pending_reads.append(op)
        return op

    async def _do_reads(self) -> None:
        async with self.running_read.needs_run() as needs_run:
            if needs_run:
                ops = self.pending_reads
                self.pending_reads = []
                merged_ops = self.merge_adjacent_reads(ops)
                # TODO we should not use a cancel scope shield, we should use the SyscallResponse API
                with trio.CancelScope(shield=True):
                    await self._unlocked_batch_read([op for op, _ in merged_ops])
                for op, orig_ops in merged_ops:
                    data = op.data
                    for orig_op in orig_ops:
                        orig_size = orig_op.src.bytesize()
                        if len(data) < orig_size:
                            raise Exception("insufficient data for original operation", len(data), orig_size)
                        orig_op.done, data = data[:orig_size], data[orig_size:]

    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        read_ops = [self._start_single_read(src) for src in ops]
        # TODO this is inefficient
        while not(all(op.done is not None for op in read_ops)):
            await self._do_reads()
        return [op.data for op in read_ops]

