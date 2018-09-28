from __future__ import annotations
from dataclasses import dataclass
import os
import typing as t
import logging
import abc

# Here we have base dataclasses which don't carry around references to a task.
# In particular, Pointer, FileDescriptor, and Path all should be in here,
# without a reference to a task.

# The ones in io.py carry a reference to a Task, and so are more convenient for users.

class SyscallInterface:
    # Throws on negative return value
    @abc.abstractmethod
    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int: ...
    # non-syscall operations which we haven't figured out how to get rid of yet
    @abc.abstractmethod
    async def close_interface(self) -> None: ...
    # when this file descriptor is readable, it means other things want to run on this thread.
    # Users of the SyscallInterface should ensure that when they block, they are monitoring this fd as well.
    other_activity_fd: t.Optional[int]


# In general, the identifiers inside these objects can be reused. Therefore, we
# can't compare the objects on the basis of the identifiers inside them.
# As long as we compare the objects with "is", we can accurately identify them
# as "the same" object.
    
@dataclass(eq=False)
class AddressSpace:
    # the pid for which this address space was created. processes
    # can't change address space, so this pid uniquely identifies this
    # address space, up to pid wraps. since we want to be robust to
    # pid wraps, don't use the pid field to track this address space,
    # instead compare the objects with "is".
    creator_pid: int
    def null(self) -> Pointer:
        return Pointer(self, 0)

    def __str__(self) -> str:
        return f"AddressSpace({self.creator_pid})"

@dataclass(eq=False)
class Pointer:
    address_space: AddressSpace
    address: int

    def __add__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.address + other)

    def __sub__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.address - other)

    def __str__(self) -> str:
        return f"Pointer({hex(self.address)}, {self.address_space})"

    def __int__(self) -> int:
        return self.address

@dataclass(eq=False)
class FDNamespace:
    creator_pid: int
    def __str__(self) -> str:
        return f"FDNamespace({self.creator_pid})"

@dataclass(eq=False)
class FileDescriptor:
    fd_namespace: FDNamespace
    number: int

    def __str__(self) -> str:
        return f"FD({self.number}, {self.fd_namespace})"

    def __int__(self) -> int:
        return self.number

@dataclass(eq=False)
class MountNamespace:
    creator_pid: int

@dataclass(eq=False)
class FSInformation:
    "Filesystem root, current working directory, and umask; controlled by CLONE_FS."
    creator_pid: int

@dataclass(eq=False)
class DirfdPathBase:
    dirfd: FileDescriptor

@dataclass(eq=False)
class RootPathBase:
    mount_namespace: MountNamespace
    fs_information: FSInformation

@dataclass(eq=False)
class CWDPathBase:
    mount_namespace: MountNamespace
    fs_information: FSInformation

@dataclass(eq=False)
class Directory:
    base: t.Union[DirfdPathBase, RootPathBase, CWDPathBase]
    # none of these will contain a "/"
    components: t.List[bytes]

    def __post_init__(self) -> None:
        for component in self.components:
            assert b"/" not in component
            assert len(component) != 0

@dataclass(eq=False)
class Path:
    dir: Directory
    basename: bytes

    def __post_init__(self) -> None:
        assert b"/" not in self.basename
        assert len(self.basename) != 0

@dataclass(eq=False)
class Path:
    base: t.Union[DirfdPathBase, RootPathBase, CWDPathBase]
    # shouldn't have a leading / if it's relative to root, we'll put that on ourselves.
    data: bytes

@dataclass(eq=False)
class ProcessNamespace:
    "The namespace for processes and process groups"
    creator_pid: int

@dataclass(eq=False)
class Process:
    namespace: ProcessNamespace
    id: int

    def __int__(self) -> int:
        return self.id

@dataclass(eq=False)
class ProcessGroup:
    namespace: ProcessNamespace
    id: int

    def __int__(self) -> int:
        return self.id

# TODO later on we'll have user namespaces too

class Task:
    def __init__(self, pid: int,
                 sysif: SyscallInterface,
                 fd_namespace: FDNamespace,
                 address_space: AddressSpace,
                 mount: MountNamespace,
                 fs: FSInformation,
    ) -> None:
        self.pid = pid
        self.sysif = sysif
        self.fd_namespace = fd_namespace
        self.address_space = address_space
        self.mount = mount
        self.fs = fs

class MemoryGateway:
    """A gateway between two tasks.
    
    Or more specifically between their address spaces and file descriptor namespaces.

    """
    # future methods will support copying between file descriptors
    @abc.abstractmethod
    async def memcpy(self, dest: Pointer, src: Pointer, n: int) -> None: ...
    @abc.abstractmethod
    async def batch_memcpy(self, ops: t.List[t.Tuple[Pointer, Pointer, int]]) -> None: ...

local_address_space = AddressSpace(os.getpid())
from rsyscall._raw import ffi, lib # type: ignore
class LocalMemoryGateway(MemoryGateway):
    i = 0
    async def memcpy(self, dest: Pointer, src: Pointer, n: int) -> None:
        if dest.address_space == src.address_space == local_address_space:
            lib.memcpy(ffi.cast('void*', dest.address), ffi.cast('void*', src.address), n)
        else:
            raise Exception("some pointer isn't in the local address space", dest, src, n)

    async def batch_memcpy(self, ops: t.List[t.Tuple[Pointer, Pointer, int]]) -> None:
        # TODO when we implement the remote support, we should try to coalesce adjacent buffers,
        # so one or both sides of the copy can be implemented with a single read or write instead of readv/writev.
        for dest, src, n in ops:
            await self.memcpy(dest, src, n)

def to_local_pointer(data: bytes) -> Pointer:
    return Pointer(local_address_space, int(ffi.cast('long', ffi.from_buffer(data))))

class RsyscallException(Exception):
    pass

class RsyscallHangup(Exception):
    pass
