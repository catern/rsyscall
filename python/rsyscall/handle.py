from __future__ import annotations
from dataclasses import dataclass, field
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import rsyscall.far
import rsyscall.near
import trio
import os
import typing as t

# This is like a far pointer plus a segment register.
# It means that, as long as it doesn't throw an exception,
# we should be able to access the object behind this pointer.
# I'll call it... an active pointer.
# Aha! No, this is something with a precise name, in fact.
# This is... a handle.
# In the sense of classic Mac OS/PalmOS/16-bit Windows memory management.
# It is useful for several reasons:

# 1. When a task changes segments through unshare, existing handles
# associated with that task can be updated to contain far pointers
# which point to the same resources in the new segment. Note that the
# near pointers are unchanged when we use unshare to change segments,
# because unshare makes a copy of the old segment.

# 2. When a task changes segments through setns, existing handles
# associated with that task can be invalidated, as they are no longer
# usable in the new namespace. New handles for the task in the new
# namespace either have to be created from pre-existing handles held
# by other tasks in the new namespace, or bootstrapped from scratch.

# 3. When the last remaining valid handle referencing a specific far
# pointer is invalidated, we can close that far pointer using the task
# in that handle.

# 4. [Future work] Handles can be automatically invalidated on
# __del__; if the handle is the last remaining valid one, the close
# action mentioned above would be added to a queue and performed
# asynchronously by a periodic garbage collection coroutine. This
# queue would be flushed whenever a task changes segments or exits.

# 5. Instead of passing both a task and a far pointer as two arguments
# to a function, a handle (which contains both) can be passed, which
# is much more convenient.

# We don't want elementwise equality, because each instance of this
# should be treated as a separate reference to the file descriptor;
# only if all the instances are invalid can we close the fd.
@dataclass(eq=False)
class FileDescriptor:
    task: Task
    near: rsyscall.near.FileDescriptor
    valid: bool = True

    @property
    def far(self) -> rsyscall.far.FileDescriptor:
        # TODO delete this property, we should go through handle
        # helper methods only, which don't check the fd table.
        if not self.valid:
            raise Exception("handle is no longer valid")
        return rsyscall.far.FileDescriptor(self.task.fd_table, self.near)

    async def invalidate(self) -> None:
        self.valid = False
        self.task.fd_handles.remove(self)

    def __str__(self) -> str:
        return f"FD({self.task}, {self.near.number})"

    # should I just take handle.Pointers instead of near or far stuff? hmm.
    # should I really require ownership in this way?
    # well, the invalidation needs to work.
    # oh hmm! if the pointer comes from another task, how does that work?
    # so I'll take far Pointers, and Union[handle.FileDescriptor, far.FileDescriptor]
    async def read(self, buf: rsyscall.far.Pointer, count: int) -> int:
        return (await rsyscall.near.read(self.task.sysif, self.near, self.task.to_near_pointer(buf), count))

    async def write(self, buf: rsyscall.far.Pointer, count: int) -> int:
        return (await rsyscall.near.write(self.task.sysif, self.near, self.task.to_near_pointer(buf), count))

class Task(rsyscall.far.Task):
    # work around breakage in mypy - it doesn't understand dataclass inheritance
    # TODO delete this
    def __init__(self,
                 sysif: rsyscall.near.SyscallInterface,
                 fd_table: rsyscall.far.FDTable,
                 address_space: rsyscall.far.AddressSpace) -> None:
        self.sysif = sysif
        self.fd_table = fd_table
        self.address_space = address_space
        self.fd_handles: t.List[FileDescriptor] = []

    def make_fd_handle(self, fd: t.Union[rsyscall.near.FileDescriptor,
                                         rsyscall.far.FileDescriptor,
                                         FileDescriptor]) -> FileDescriptor:
        if isinstance(fd, rsyscall.near.FileDescriptor):
            near = fd
        elif isinstance(fd, rsyscall.far.FileDescriptor):
            near = self.to_near_fd(fd)
        elif isinstance(fd, FileDescriptor):
            near = self.to_near_fd(fd.far)
        else:
            raise Exception("bad fd type", fd, type(fd))
        handle = FileDescriptor(self, near)
        self.fd_handles.append(handle)
        return handle

    async def unshare_files(self) -> None:
        pass

@dataclass
class Pipe:
    read: FileDescriptor
    write: FileDescriptor

@dataclass
class MemoryMapping:
    task: rsyscall.far.Task
    far: rsyscall.far.MemoryMapping

    async def munmap(self) -> None:
        await rsyscall.far.munmap(self.task, self.far)

