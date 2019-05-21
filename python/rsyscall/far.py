from __future__ import annotations
from dataclasses import dataclass
import typing as t
import os
import signal
import rsyscall.near
import contextlib
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer

# These are like segment ids.
# They set eq=False because they are identified by their Python object identity,
# in lieu of a real identifier.
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

# These are like far pointers.
@dataclass(eq=False)
class Process:
    namespace: PidNamespace
    near: rsyscall.near.Process

    def __int__(self) -> int:
        return int(self.near)

@dataclass
class ProcessGroup:
    namespace: PidNamespace
    near: rsyscall.near.ProcessGroup

    def __int__(self) -> int:
        return int(self.near)

class NamespaceMismatchError(Exception):
    pass

class FDTableMismatchError(NamespaceMismatchError):
    pass

class AddressSpaceMismatchError(NamespaceMismatchError):
    pass

@dataclass(eq=False)
class FSInformation:
    "Filesystem root, current working directory, and umask; controlled by CLONE_FS."
    creator_pid: int

# This is like a segment register, if a segment register was write-only. Then
# we'd need to maintain the knowledge of what the segment register was set to,
# outside the segment register itself. That's what we do here.
@dataclass
class Task:
    sysif: rsyscall.near.SyscallInterface
    fd_table: FDTable
    address_space: AddressSpace
    fs: FSInformation
    # at the moment, our own pidns and our child pidns are never different.
    # but they could be different, if we do an unshare(NEWPID).
    # TODO make separate child_pidns and use properly
    pidns: PidNamespace

    async def _borrow_optional(self, stack: contextlib.ExitStack, ptr: t.Optional[Pointer]
    ) -> t.Optional[rsyscall.near.Pointer]:
        if ptr is None:
            return None
        else:
            stack.enter_context(ptr.borrow(self))
            return ptr.near

    def __post_init__(self) -> None:
        pass
