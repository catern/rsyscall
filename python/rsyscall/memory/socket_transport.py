from __future__ import annotations
from rsyscall.far import Pointer
from dataclasses import dataclass, field
from rsyscall.concurrency import OneAtATime
from rsyscall.memory.ram import RAM
from rsyscall.base import MemoryTransport
import rsyscall.base as base
import rsyscall.near as near
import rsyscall.handle as handle
import typing as t
import trio

@dataclass
class ReadOp:
    src: Pointer
    n: int
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
        if not self.done:
            raise Exception("not done yet")

def merge_adjacent_writes(write_ops: t.List[t.Tuple[Pointer, bytes]]) -> t.List[t.Tuple[Pointer, bytes]]:
    "Note that this is only effective inasmuch as the list is sorted."
    if len(write_ops) == 0:
        return []
    write_ops = sorted(write_ops, key=lambda op: int(op[0]))
    outputs: t.List[t.Tuple[Pointer, bytes]] = []
    last_pointer, last_data = write_ops[0]
    for pointer, data in write_ops[1:]:
        if int(last_pointer + len(last_data)) == int(pointer):
            last_data += data
        elif int(last_pointer + len(last_data)) > int(pointer):
            raise Exception("pointers passed to memcpy are overlapping!")
        else:
            outputs.append((last_pointer, last_data))
            last_pointer, last_data = pointer, data
    outputs.append((last_pointer, last_data))
    return outputs

@dataclass
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
    local: AsyncFileDescriptor
    local_ram: RAM
    remote: handle.FileDescriptor
    pending_writes: t.List[WriteOp] = field(default_factory=list)
    running_write: OneAtATime = field(default_factory=OneAtATime)
    pending_reads: t.List[ReadOp] = field(default_factory=list)
    running_read: OneAtATime = field(default_factory=OneAtATime)

    @staticmethod
    def merge_adjacent_reads(read_ops: t.List[ReadOp]) -> t.List[t.Tuple[ReadOp, t.List[ReadOp]]]:
        "Note that this is only effective inasmuch as the list is sorted."
        # TODO BUG HACK
        # This stuff is colossally broken!!
        # We are mutating the operations that were passed in to create the aggregate operation!
        # That means the aggregate operation (last_op) is one of the orig_ops!
        # That's totally broke!!!!
        # we'll fix this when we rewrite the transport stuff.
        if len(read_ops) == 0:
            return []
        read_ops = sorted(read_ops, key=lambda op: int(op.src))
        last_op = read_ops[0]
        last_orig_ops = [last_op]
        outputs: t.List[t.Tuple[ReadOp, t.List[ReadOp]]] = []
        for op in read_ops[1:]:
            if int(last_op.src + last_op.n) == int(op.src):
                last_op.n += op.n
                last_orig_ops.append(op)
            elif int(last_op.src + last_op.n) == int(op.src):
                raise Exception("pointers passed to memcpy are overlapping!")
            else:
                outputs.append((last_op, last_orig_ops))
                last_op = op
                last_orig_ops = [op]
        outputs.append((last_op, last_orig_ops))
        return outputs

    def inherit(self, task: handle.Task) -> SocketMemoryTransport:
        return SocketMemoryTransport(self.local, self.local_ram, task.make_fd_handle(self.remote))

    async def _unlocked_single_write(self, dest: Pointer, data: bytes) -> None:
        # need an additional cap: to turn bytes to a pointer.
        src = base.to_local_pointer(data)
        n = len(data)
        rtask = self.remote.task
        near_read_fd = self.remote.near
        near_dest = rtask.to_near_pointer(dest)
        wtask = self.local.underlying.task.base
        near_write_fd = self.local.underlying.handle.near
        near_src = wtask.to_near_pointer(src)
        async def read() -> None:
            i = 0
            while (n - i) > 0:
                ret = await near.read(rtask.sysif, near_read_fd, near_dest+i, n-i)
                i += ret
        async def write() -> None:
            i = 0
            while (n - i) > 0:
                ret = await self.local.write_raw(wtask.sysif, near_write_fd, near_src+i, n-i)
                i += ret
        async with trio.open_nursery() as nursery:
            nursery.start_soon(read)
            nursery.start_soon(write)

    async def _unlocked_batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        ops = sorted(ops, key=lambda op: int(op[0]))
        ops = merge_adjacent_writes(ops)
        if len(ops) <= 1:
            [(dest, data)] = ops
            await self._unlocked_single_write(dest, data)
        else:
            # TODO use an iovec
            # build the full iovec at the start
            # write it over with unlocked_single_write
            # call readv
            # on partial read, fall back to unlocked_single_write for the rest of that section,
            # then go back to an incremented iovec
            for dest, data in ops:
                await self._unlocked_single_write(dest, data)

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
                with trio.open_cancel_scope(shield=True):
                    await self._unlocked_batch_write([(write.dest, write.data) for write in writes])
                for write in writes:
                    write.done = True

    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        write_ops = [self._start_single_write(dest, data) for (dest, data) in ops]
        await self._do_writes()
        for op in write_ops:
            op.assert_done()

    async def _unlocked_single_read(self, src: Pointer, n: int) -> bytes:
        buf = bytearray(n)
        dest = base.to_local_pointer(buf)
        rtask = self.local.underlying.task.base
        near_dest = rtask.to_near_pointer(dest)
        near_read_fd = self.local.underlying.handle.near
        wtask = self.remote.task
        near_src = wtask.to_near_pointer(src)
        near_write_fd = self.remote.near
        async def read() -> None:
            i = 0
            while (n - i) > 0:
                ret = await self.local.read_raw(rtask.sysif, near_read_fd, near_dest+i, n-i)
                i += ret
        async def write() -> None:
            i = 0
            while (n - i) > 0:
                ret = await near.write(wtask.sysif, near_write_fd, near_src+i, n-i)
                i += ret
        async with trio.open_nursery() as nursery:
            nursery.start_soon(read)
            nursery.start_soon(write)
        return bytes(buf)

    async def _unlocked_batch_read(self, ops: t.List[ReadOp]) -> None:
        for op in ops:
            op.done = await self._unlocked_single_read(op.src, op.n)

    def _start_single_read(self, dest: Pointer, n: int) -> ReadOp:
        op = ReadOp(dest, n)
        self.pending_reads.append(op)
        return op

    async def _do_reads(self) -> None:
        async with self.running_read.needs_run() as needs_run:
            if needs_run:
                ops = self.pending_reads
                self.pending_reads = []
                merged_ops = self.merge_adjacent_reads(ops)
                # TODO we should not use a cancel scope shield, we should use the SyscallResponse API
                with trio.open_cancel_scope(shield=True):
                    await self._unlocked_batch_read([op for op, _ in merged_ops])
                for op, orig_ops in merged_ops:
                    data = op.data
                    for orig_op in orig_ops:
                        if len(data) < orig_op.n:
                            raise Exception("insufficient data for original operation", len(data), orig_op.n)
                        orig_op.done, data = data[:orig_op.n], data[orig_op.n:]

    async def batch_read(self, ops: t.List[t.Tuple[Pointer, int]]) -> t.List[bytes]:
        read_ops = [self._start_single_read(src, n) for src, n in ops]
        # TODO this is inefficient
        while not(all(op.done is not None for op in read_ops)):
            await self._do_reads()
        return [op.data for op in read_ops]

