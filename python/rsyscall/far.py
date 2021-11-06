"""Definitions of namespaces and identifiers tagged with a namespace.

In the analogy to near and far pointers, this file is where we define
segment ids and far pointers. A far pointer is a near pointer plus a
segment id. See `rsyscall.near` for more on this analogy.

Note, we don't actually define any far pointers at the moment. We used
to, but we removed them all in favor of handles; handles are more
robust.

"""
from __future__ import annotations
from dataclasses import dataclass
import contextlib
import rsyscall.near
import typing as t
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer

@dataclass(eq=False)
class File:
    """An opaque representation of a file, possibly referenced by file descriptors or memory mappings.

    Specifically, this represents what in POSIXese is called an "open file description".

    We use this as an identifier, compared by Python object identity ("is"), to track
    whether two fds or mmaps are referring to the same underlying file.

    This doesn't really fit into the analogy to near and far pointers. In that analogy,
    this class would represent the actual memory being addressed. Not sure what to think
    of that.

    """
    
    pass

#### Segment ids
@dataclass(eq=False)
class FDTable:
    """An opaque representation of an existing file descriptor table, compared with "is".

    This is the namespace in which a near.FileDescriptor is valid.

    For debugging purposes, we take `creator_pid` as an argument. But pids don't uniquely
    identify fd tables, because processes can change fd table, such as by calling
    unshare(CLONE.FILES), while leaving other processes behind in their old address space.

    There aren't any useful, efficient identifiers for file descriptor tables, so we
    compare this object with Python object identify ("is") to see whether two file
    descriptor tables referenced by two Tasks are the same.

    """
    creator_pid: int

    def __str__(self) -> str:
        return f"FDTable({self.creator_pid})"

@dataclass(eq=False)
class AddressSpace:
    """An opaque representation of an existing address space, compared with "is".

    This is the namespace in which a near.Address or near.MemoryMapping is valid.

    For debugging purposes, we take `creator_pid` as an argument. But pids don't uniquely
    identify address spaces, because processes can change address space, such as by
    calling execve, while leaving other processes behind in their old address space.

    There aren't any useful, efficient identifiers for address spaces, so we compare this
    object with Python object identify ("is") to see whether two address spaces referenced
    by two Tasks are the same.

    """
    creator_pid: int
    def __str__(self) -> str:
        return f"AddressSpace({self.creator_pid})"

@dataclass(eq=False)
class PidNamespace:
    """An opaque representation of an existing pid namespace, compared with "is"

    This is the namespace in which a near.Process or near.ProcessGroup is valid. Thread
    groups and sessions are also relative to a pid namespace, but we don't currently
    represent those.

    For debugging purposes, we take `creator_pid` as an argument. But pids don't uniquely
    identify pid namespaces, because processes can change pid namespace, such as by
    calling execve, while leaving other processes behind in their old pid namespace.

    There aren't any useful, efficient identifiers for pid namespaces, so we compare this
    object with Python object identify ("is") to see whether two pid namespaces referenced
    by two Tasks are the same.

    """
    creator_pid: int

class NamespaceMismatchError(Exception):
    "An object was used with a task whose namespaces it doesn't match"
    pass

class FDTableMismatchError(NamespaceMismatchError):
    "A file descriptor was used with a Task with a different fd table"
    pass

class AddressSpaceMismatchError(NamespaceMismatchError):
    "A memory address or memory mapping was used with a Task with a different address space"
    pass

#### Segment register
@dataclass(eq=False)
class Task:
    """A wrapper around `SyscallInterface` which tracks the namespaces of the underlying process

    Note that this is a base class for the more fully featured `rsyscall.Task`.

    We store namespace objects to represent the namespaces that we believe that underlying
    processes is in. Since we have complete control over the process, we can make sure
    this belief is accurate, by updating our stored namespaces when the process changes
    namespace. That isn't done here; it's done in handle.Task.

    Currently, we store only one `PidNamespace`. But each process actually has two pid
    namespaces: 

    - the process's own pid namespace, which determines the pids returned from getpid,
      clone, and other syscalls.
    - the pid namespace that new children will be in.

    The two pid namespaces only differ if we call unshare(CLONE.NEWPID). Currently we
    don't do that because unshare(CLONE.NEWPID) makes monitoring children more complex,
    since they can be deleted without leaving a zombie at any time if the pid namespace
    shuts down. But if we did call unshare(CLONE.NEWPID), we'd need to handle this right.

    In the analogy to near and far pointers, this is like a segment register, if a segment
    register was write-only. Then we'd need to maintain the knowledge of what the segment
    register was set to, outside the segment register itself. That's what we do here.

    There actually were systems where segment registers were, if not quite write-only, at
    least expensive to set and expensive to read. For example, x86_64 - the FS and GS
    segment registers can only be set via syscall. If you wanted to use segmentation on
    such systems, you'd probably have a structure much like this one.

    """
    sysif: rsyscall.near.SyscallInterface
    near_process: rsyscall.near.Process
    fd_table: FDTable
    address_space: AddressSpace
    pidns: PidNamespace

    def _borrow_optional(self, stack: contextlib.ExitStack, ptr: t.Optional[Pointer]
    ) -> t.Optional[rsyscall.near.Address]:
        if ptr is None:
            return None
        else:
            stack.enter_context(ptr.borrow(self))
            return ptr.near

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return f"Task({self.near_process})"

    def __post_init__(self) -> None:
        pass
