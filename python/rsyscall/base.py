from __future__ import annotations
from dataclasses import dataclass
import os
import typing as t
import logging
import abc
import socket
import struct
import enum
import signal

# Here we have base dataclasses which don't carry around references to a task.
# In particular, Pointer, FileDescriptor, and Path all should be in here,
# without a reference to a task.
# These things are all "far pointers" in terms of memory segmentation.

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

@dataclass
class Task:
    sysif: SyscallInterface
    fd_namespace: FDNamespace
    address_space: AddressSpace

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
    def __init__(self, space_a: AddressSpace,
                 space_b: AddressSpace) -> None:
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

T_addr = t.TypeVar('T_addr', bound='Address')
class Address:
    addrlen: int
    @classmethod
    @abc.abstractmethod
    def parse(cls: t.Type[T_addr], data: bytes) -> T_addr: ...
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...

class PathTooLongError(ValueError):
    pass

class UnixAddress(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_un')
    def __init__(self, path: bytes) -> None:
        if len(path) > 108:
            raise PathTooLongError("path is longer than the maximum unix address size")
        self.path = path

    T = t.TypeVar('T', bound='UnixAddress')
    @classmethod
    def parse(cls: t.Type[T], data: bytes) -> T:
        header = ffi.sizeof('sa_family_t')
        buf = ffi.from_buffer(data)
        if len(data) < header:
            raise Exception("data too smalllll")
        struct = ffi.cast('struct sockaddr_un*', buf)
        if struct.sun_family != lib.AF_UNIX:
            raise Exception("sun_family must be", lib.AF_UNIX, "is instead", header.sun_family)
        if len(data) == header:
            # unnamed socket, name is empty
            length = 0
        elif struct.sun_path[0] == b'\0':
            # abstract socket, entire buffer is part of path
            length = len(data) - header
        else:
            # TODO handle the case where there's no null terminator
            # pathname socket, path is null-terminated
            length = lib.strlen(struct.sun_path)
        return cls(bytes(ffi.buffer(struct.sun_path, length)))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_un*', (lib.AF_UNIX, self.path))
        real_length = ffi.sizeof('sa_family_t') + len(self.path) + 1
        return bytes(ffi.buffer(addr))[:real_length]

    def __str__(self) -> str:
        return f"UnixAddress({self.path})"

class InetAddress(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_in')
    def __init__(self, port: int, addr: int) -> None:
        # these are in host byte order, of course
        self.port = port
        self.addr = addr

    T = t.TypeVar('T', bound='InetAddress')
    @classmethod
    def parse(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct sockaddr_in*', ffi.from_buffer(data))
        if struct.sin_family != lib.AF_INET:
            raise Exception("sin_family must be", lib.AF_INET, "is instead", struct.sin_family)
        return cls(socket.ntohs(struct.sin_port), socket.ntohl(struct.sin_addr.s_addr))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_in*', (lib.AF_INET, socket.htons(self.port), (socket.htonl(self.addr),)))
        return ffi.buffer(addr)

    def addr_as_string(self) -> str:
        "Returns the addr portion of this address in 127.0.0.1 form"
        return socket.inet_ntoa(struct.pack("!I", self.addr))

    def __str__(self) -> str:
        return f"InetAddress({self.addr_as_string()}:{self.port})"

class IdType(enum.IntEnum):
    PID = lib.P_PID # Wait for the child whose process ID matches id.
    PGID = lib.P_PGID # Wait for any child whose process group ID matches id.
    ALL = lib.P_ALL # Wait for any child; id is ignored.

class EpollCtlOp(enum.IntEnum):
    ADD = lib.EPOLL_CTL_ADD
    MOD = lib.EPOLL_CTL_MOD
    DEL = lib.EPOLL_CTL_DEL

class ChildCode(enum.Enum):
    EXITED = lib.CLD_EXITED # child called _exit(2)
    KILLED = lib.CLD_KILLED # child killed by signal
    DUMPED = lib.CLD_DUMPED # child killed by signal, and dumped core
    STOPPED = lib.CLD_STOPPED # child stopped by signal
    TRAPPED = lib.CLD_TRAPPED # traced child has trapped
    CONTINUED = lib.CLD_CONTINUED # child continued by SIGCONT

class UncleanExit(Exception):
    pass

@dataclass
class ChildEvent:
    code: ChildCode
    pid: int
    uid: int
    exit_status: t.Optional[int]
    sig: t.Optional[signal.Signals]

    @staticmethod
    def make(code: ChildCode, pid: int, uid: int, status: int):
        if code is ChildCode.EXITED:
            return ChildEvent(code, pid, uid, status, None)
        else:
            return ChildEvent(code, pid, uid, None, signal.Signals(status))

    def died(self) -> bool:
        return self.code in [ChildCode.EXITED, ChildCode.KILLED, ChildCode.DUMPED]
    def clean(self) -> bool:
        return self.code == ChildCode.EXITED and self.exit_status == 0

    def check(self) -> None:
        if self.clean():
            return None
        else:
            raise UncleanExit(self)

    def killed_with(self) -> signal.Signals:
        """What signal was the child killed with?

        Throws if the child was not killed with a signal.

        """
        if not self.died():
            raise Exception("Child isn't dead")
        if self.sig is None:
            raise Exception("Child wasn't killed with a signal")
        return self.sig
