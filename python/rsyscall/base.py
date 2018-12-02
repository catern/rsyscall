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
from rsyscall.far import AddressSpace, FDTable, Pointer
from rsyscall.far import Process, ProcessGroup, FileDescriptor
from rsyscall.handle import Task
from rsyscall.near import SyscallInterface
from rsyscall.exceptions import RsyscallException, RsyscallHangup
import rsyscall.near

# Here we have base dataclasses which don't carry around references to a task.
# In particular, Pointer, FileDescriptor, and Path all should be in here,
# without a reference to a task.
# These things are all "far pointers" in terms of memory segmentation.

# The ones in io.py carry a reference to a Task, and so are more convenient for users.

@dataclass(eq=False)
class MountNamespace:
    creator_pid: int

@dataclass(eq=False)
class FSInformation:
    "Filesystem root, current working directory, and umask; controlled by CLONE_FS."
    creator_pid: int

@dataclass
class DirfdPathBase:
    dirfd: FileDescriptor

@dataclass
class RootPathBase:
    mount_namespace: MountNamespace
    fs_information: FSInformation

@dataclass
class CWDPathBase:
    mount_namespace: MountNamespace
    fs_information: FSInformation

@dataclass
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

    def __truediv__(self, path_element: t.Union[str, bytes]) -> Path:
        element: bytes = os.fsencode(path_element)
        if b"/" in element:
            raise Exception("no / allowed in path elements, do it one by one")
        return Path(self.base, self.components+[element])

    @staticmethod
    def from_bytes(mount_namespace: MountNamespace, fs_information: FSInformation, path: bytes) -> Path:
        if path.startswith(b"/"):
            return Path(RootPathBase(mount_namespace, fs_information), path[1:].split(b"/"))
        else:
            return Path(CWDPathBase(mount_namespace, fs_information), path.split(b"/"))

    def unix_address(self) -> UnixAddress:
        return UnixAddress(bytes(self))

    def __bytes__(self) -> bytes:
        pathdata = b"/".join(self.components)
        if isinstance(self.base, RootPathBase):
            ret = b"/" + pathdata
        elif isinstance(self.base, CWDPathBase):
            ret = pathdata
        elif isinstance(self.base, DirfdPathBase):
            ret = b"/proc/self/fd/" + bytes(int(self.base.dirfd)) + b"/" + pathdata
        else:
            raise Exception("invalid base type")
        return ret

    def __str__(self) -> str:
        return bytes(self).decode()

# TODO later on we'll have user namespaces too

class MemoryGateway:
    """A gateway between two tasks.
    
    Or more specifically between their address spaces and file descriptor namespaces.

    """
    @abc.abstractmethod
    def inherit(self, task: Task) -> MemoryGateway: ...
    # future methods will support copying between file descriptors
    @abc.abstractmethod
    async def memcpy(self, dest: Pointer, src: Pointer, n: int) -> None: ...
    @abc.abstractmethod
    async def batch_memcpy(self, ops: t.List[t.Tuple[Pointer, Pointer, int]]) -> None: ...

local_address_space = AddressSpace(os.getpid())

class InvalidAddressSpaceError(Exception):
    pass

from rsyscall._raw import ffi, lib # type: ignore
class LocalMemoryGateway(MemoryGateway):
    def inherit(self, task: Task) -> LocalMemoryGateway:
        return self

    async def memcpy(self, dest: Pointer, src: Pointer, n: int) -> None:
        neardest = local_address_space.to_near(dest)
        nearsrc = local_address_space.to_near(src)
        lib.memcpy(ffi.cast('void*', int(neardest)), ffi.cast('void*', int(nearsrc)), n)

    async def batch_memcpy(self, ops: t.List[t.Tuple[Pointer, Pointer, int]]) -> None:
        # TODO when we implement the remote support, we should try to coalesce adjacent buffers,
        # so one or both sides of the copy can be implemented with a single read or write instead of readv/writev.
        for dest, src, n in ops:
            await self.memcpy(dest, src, n)

def cffi_to_local_pointer(cffi_object) -> Pointer:
    return Pointer(local_address_space, rsyscall.near.Pointer(int(ffi.cast('long', cffi_object))))

def to_local_pointer(data: bytes) -> Pointer:
    return cffi_to_local_pointer(ffi.from_buffer(data))

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
        raise InvalidAddressSpaceError("some pointer isn't in the local address space", dest, src, n)

    async def batch_memcpy(self, ops: t.List[t.Tuple[Pointer, Pointer, int]]) -> None:
        # TODO when we implement the remote support, we should try to coalesce adjacent buffers,
        # so one or both sides of the copy can be implemented with a single read or write instead of readv/writev.
        for dest, src, n in ops:
            await self.memcpy(dest, src, n)

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
