from __future__ import annotations
from dataclasses import dataclass
import typing as t
import abc

# Here we have base dataclasses which don't carry around references to a task.
# In particular, Pointer, FileDescriptor, and Path all should be in here,
# without a reference to a task.

# The ones in io.py carry a reference to a Task, and so are more convenient for users.

class SyscallInterface:
    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int: ...
    # non-syscall operations which we haven't figured out how to get rid of yet
    async def close_interface(self) -> None: ...
    async def wait_readable(self, fd: int) -> None: ...
    
class AddressSpace:
    def null(self) -> Pointer:
        return Pointer(self, 0)

    def __str__(self) -> str:
        return f"AddressSpace({id(self)})"

local_address_space = AddressSpace()

@dataclass
class Pointer:
    address_space: AddressSpace
    address: int

    def __add__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.address + other)

    def __sub__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.address - other)

    def __str__(self) -> str:
        return f"Pointer({self.address_space}, {hex(self.address)})"

    def __int__(self) -> int:
        return self.address

class FDNamespace:
    def null(self) -> FileDescriptor:
        return FileDescriptor(self, -1)

    def __str__(self) -> str:
        return f"FDNamespace({id(self)})"

@dataclass
class FileDescriptor:
    fd_namespace: FDNamespace
    number: int

    def __str__(self) -> str:
        return f"FileDescriptor({self.fd_namespace}, {self.number})"

    def __int__(self) -> int:
        return self.number

class MountNamespace:
    pass

class FSInformation:
    "Filesystem root, current working directory, and umask; controlled by CLONE_FS."
    pass

@dataclass
class DirfdPathBase:
    dirfd: FileDescriptor

@dataclass
class RootPathBase:
    namespace: MountNamespace
    fs_information: FSInformation

@dataclass
class CWDPathBase:
    namespace: MountNamespace
    fs_information: FSInformation

@dataclass
class Path:
    base: t.Union[DirfdPathBase, RootPathBase, CWDPathBase]
    # shouldn't have a leading / if it's relative to root, we'll put that on ourselves.
    data: bytes

class ProcessNamespace:
    "The namespace for processes and process groups"
    pass

@dataclass
class Process:
    namespace: ProcessNamespace
    id: int

    def __int__(self) -> int:
        return self.id

@dataclass
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
