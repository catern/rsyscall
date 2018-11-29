from __future__ import annotations
from rsyscall.base import Pointer, RsyscallException, RsyscallHangup
from rsyscall.base import T_addr, UnixAddress, PathTooLongError, InetAddress
from dataclasses import dataclass
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import rsyscall.far
import rsyscall.near
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
@dataclass
class FileDescriptor:
    task: rsyscall.far.Task
    far: rsyscall.far.FileDescriptor

    def to_near(self) -> rsyscall.near.FileDescriptor:
        return self.task.to_near_fd(self.far)

    def __str__(self) -> str:
        return f"FD({self.task}, {self.far.fd_table}, {self.far.near.number})"

    async def read(self, buf: rsyscall.far.Pointer, count: int) -> int:
        return (await rsyscall.far.read(self.task, self.far, buf, count))

    async def write(self, buf: rsyscall.far.Pointer, count: int) -> int:
        return (await rsyscall.far.write(self.task, self.far, buf, count))

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

