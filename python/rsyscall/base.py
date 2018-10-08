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
    # Typically, this is in fact the fd which the rsyscall server reads for incoming system calls!
    activity_fd: t.Optional[FileDescriptor]


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
class Path:
    base: t.Union[DirfdPathBase, RootPathBase, CWDPathBase]
    # The typical representation of a path as foo/bar/baz\0,
    # is really just a serialization of a list of components using / as the in-band separator.
    # We represent paths directly as the list they really are.
    components: t.List[bytes]
    def __post_init__(self) -> None:
        # Each component has no / in it and is non-zero length.
        for component in self.components:
            assert len(component) != 0
            assert b"/" not in component

    def split(self) -> t.Tuple[Path, bytes]:
        return Path(self.base, self.components[:-1]), self.components[-1]

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

class PeerMemoryGateway(MemoryGateway):
    def __init__(self, space_a: AddressSpace, space_b: AddressSpace) -> None:
        pass

    async def memcpy(self, dest: Pointer, src: Pointer, n: int) -> None:
        # write memory from dest pointer into that pointer's address space's data sending fd
        # read from src pointer's address space's data receiving fd into src pointer
        # they definitely need to be async since the reads and writes can block a lot.
        # do we need to prepare the async fd in advance? the epollfd? is that it?
        # that's certainly one trick we could do.
        # how will that work on a remote host? I guess the rsyscall bootstrap will prepare it autonomously... and tell us it...
        # um, well in that case we could have the bootstrap do that even locally
        # well we will never actually be in a different address space locally, there's no benefit to it, so...
        # for now let's prepare it in the parent and pass it down, yeah
        # and we'll send the write and the read in parallel, which should be fine.
        # ok! seems good.
        # we'll register things in the host process, and also make things in the host process, then inherit them down
        if dest.address_space == src.address_space == local_address_space:
            lib.memcpy(ffi.cast('void*', dest.address), ffi.cast('void*', src.address), n)
        else:
            raise Exception("some pointer isn't in the local address space", dest, src, n)

    async def batch_memcpy(self, ops: t.List[t.Tuple[Pointer, Pointer, int]]) -> None:
        # TODO when we implement the remote support, we should try to coalesce adjacent buffers,
        # so one or both sides of the copy can be implemented with a single read or write instead of readv/writev.
        for dest, src, n in ops:
            await self.memcpy(dest, src, n)

class RsyscallException(Exception):
    pass

class RsyscallHangup(Exception):
    pass
