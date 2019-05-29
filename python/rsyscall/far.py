"""Definitions of namespaces and identifiers tagged with a namespace

In the analogy to near and far pointers, this file is where we define
segment ids and far pointers. A far pointer is a near pointer plus a
segment id. See near.py for more on this analogy.

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

#### Segment ids
# These set eq=False because they are identified by their Python
# object identity, in lieu of a real identifier.
@dataclass(eq=False)
class FDTable:
    # this is just for debugging; pids don't uniquely identify fd tables because
    # processes can change fd table (such as through unshare(CLONE_FILES))
    creator_pid: int

    def __str__(self) -> str:
        return f"FDTable({self.creator_pid})"

@dataclass(eq=False)
class AddressSpace:
    # the pid for which this address space was created. processes can't change
    # address space, so this pid uniquely identifies this address space, up to
    # pid wraps. since we want to be robust to pid wraps, don't use the pid
    # field to track this address space, instead compare the objects with "is".
    creator_pid: int
    def __str__(self) -> str:
        return f"AddressSpace({self.creator_pid})"

@dataclass(eq=False)
class PidNamespace:
    "The namespace for tasks, processes, process groups, and sessions"
    creator_pid: int

class NamespaceMismatchError(Exception):
    pass

class FDTableMismatchError(NamespaceMismatchError):
    pass

class AddressSpaceMismatchError(NamespaceMismatchError):
    pass

#### Far pointers
# lol we deleted them all

#### Segment register
# This is like a segment register, if a segment register was write-only. Then
# we'd need to maintain the knowledge of what the segment register was set to,
# outside the segment register itself. That's what we do here.
@dataclass
class Task:
    sysif: rsyscall.near.SyscallInterface
    fd_table: FDTable
    address_space: AddressSpace
    # at the moment, our own pidns and our child pidns are never different.
    # but they could be different, if we do an unshare(NEWPID).
    # TODO make separate child_pidns and use properly
    pidns: PidNamespace

    def _borrow_optional(self, stack: contextlib.ExitStack, ptr: t.Optional[Pointer]
    ) -> t.Optional[rsyscall.near.Pointer]:
        if ptr is None:
            return None
        else:
            stack.enter_context(ptr.borrow(self))
            return ptr.near

    def __post_init__(self) -> None:
        pass
