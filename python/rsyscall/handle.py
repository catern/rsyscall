from __future__ import annotations
from dataclasses import dataclass, field
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import gc
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

fd_table_to_near_to_handles: t.Dict[rsyscall.near.FileDescriptor, t.List[FileDescriptor]] = {}

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
        fd_table_to_near_to_handles.setdefault(self.fd_table, {}).setdefault(near, []).append(handle)
        return handle

    async def unshare_files(self, do_unshare: t.Callable[[
            # fds to close in the old space
            t.List[rsyscall.near.FileDescriptor],
            # fds to copy into the new space
            t.List[rsyscall.near.FileDescriptor]
    ], t.Awaitable[None]]) -> None:
        old_fd_table = self.fd_table
        # TODO get the pid from the SyscallInterface
        new_fd_table = rsyscall.far.FDTable(0)
        new_near_to_handles = {}
        fd_table_to_near_to_handles[new_fd_table] = new_near_to_handles
        for handle in self.fd_handles:
            new_near_to_handles.setdefault(handle.near, []).append(handle)
        self.fd_table = new_fd_table
        snapshot_old_near_to_handles = copy.deepcopy(old_near_to_handles)
        needs_close: t.Set[rsyscall.near.FileDescriptor] = []
        for handle in self.fd_handles:
            near = handle.near
            snapshot_old_near_to_handles[near].remove(handle)
            # If the list is empty, it means the only handles for this fd in the old fd
            # table are our own, and we therefore want to close this fd. No further
            # handles for this fd can be created, even while we are asynchronously calling
            # unshare, because no-one can make a new handle from one of ours, because we
            # changed our Task.fd_table to point to a new fd table.
            if len(old_near_to_handles[near]) == 0:
                needs_close.append(near)
        await do_unshare(needs_close, [fd.near for fd in self.fd_handles])
        # We can only remove our handles from the handle lists after the unshare is done
        # and the fds are safely copied, because otherwise someone else running GC on the
        # old fd table would close our fds when they notice there are no more handles.
        old_near_to_handles = fd_table_to_near_to_handles.setdefault(old_fd_table, {})
        for handle in self.fd_handles:
            old_near_to_handles[near].remove(handle)

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

