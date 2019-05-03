from __future__ import annotations
from dataclasses import dataclass
import typing as t
import os
import signal
import rsyscall.near

from rsyscall.sys.epoll import EpollCtlOp

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

    def to_near(self, file_descriptor: FileDescriptor) -> rsyscall.near.FileDescriptor:
        if file_descriptor.fd_table == self:
            return file_descriptor.near
        else:
            raise FDTableMismatchError(file_descriptor.fd_table, self)

@dataclass(eq=False)
class AddressSpace:
    # the pid for which this address space was created. processes can't change
    # address space, so this pid uniquely identifies this address space, up to
    # pid wraps. since we want to be robust to pid wraps, don't use the pid
    # field to track this address space, instead compare the objects with "is".
    creator_pid: int
    def null(self) -> Pointer:
        return Pointer(self, rsyscall.near.Pointer(0))

    def __str__(self) -> str:
        return f"AddressSpace({self.creator_pid})"

    def to_near(self, pointer: Pointer) -> rsyscall.near.Pointer:
        if pointer.address_space == self:
            return pointer.near
        else:
            raise AddressSpaceMismatchError("pointer", pointer, "doesn't match address space", self)

# These are like far pointers.
@dataclass
class FileDescriptor:
    fd_table: FDTable
    near: rsyscall.near.FileDescriptor

    def __str__(self) -> str:
        return f"FD({self.fd_table}, {self.near.number})"

    def __int__(self) -> int:
        return int(self.near)

@dataclass
class Pointer:
    address_space: AddressSpace
    near: rsyscall.near.Pointer

    def __add__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.near + other)

    def __sub__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.near - other)

    def __str__(self) -> str:
        return f"Pointer({self.address_space}, {hex(self.near.address)})"

    def __repr__(self) -> str:
        return f"Pointer({self.address_space}, {hex(self.near.address)})"

    def __int__(self) -> int:
        return int(self.near)

@dataclass(eq=False)
class PidNamespace:
    "The namespace for tasks, processes, process groups, and sessions"
    creator_pid: int

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

@dataclass(eq=False)
class NetNamespace:
    """The namespace for networking resource: devices, routing tables, etc.

    Also controls the abstract namespace for Unix domain sockets.
    """
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
    netns: NetNamespace

    def to_near_pointer(self, pointer: Pointer) -> rsyscall.near.Pointer:
        return self.address_space.to_near(pointer)

    def to_near_fd(self, file_descriptor: FileDescriptor) -> rsyscall.near.FileDescriptor:
        return self.fd_table.to_near(file_descriptor)
