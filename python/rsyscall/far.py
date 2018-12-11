from __future__ import annotations
from dataclasses import dataclass
import typing as t
import os
import rsyscall.near

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

    def to_near_mapping(self, mapping: MemoryMapping) -> rsyscall.near.MemoryMapping:
        if mapping.address_space == self:
            return mapping.near
        else:
            raise AddressSpaceMismatchError("mapping", mapping, "doesn't match address space", self)

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

@dataclass
class MemoryMapping:
    address_space: AddressSpace
    near: rsyscall.near.MemoryMapping

    def as_pointer(self) -> Pointer:
        return Pointer(self.address_space, self.near.as_pointer())

    def __str__(self) -> str:
        if self.near.page_size == 4096:
            return f"MMap({self.address_space}, {hex(self.near.address)}, {self.near.length})"
        else:
            return f"MMap({self.address_space}, pgsz={self.near.page_size}, {hex(self.near.address)}, {self.near.length})"

    def __repr__(self) -> str:
        return str(self)

@dataclass(eq=False)
class ProcessNamespace:
    "The namespace for processes and process groups"
    creator_pid: int

@dataclass
class Process:
    namespace: ProcessNamespace
    near: rsyscall.near.Process

    def __int__(self) -> int:
        return int(self.near)

@dataclass
class ProcessGroup:
    namespace: ProcessNamespace
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
    root: rsyscall.near.DirectoryFile
    cwd: rsyscall.near.DirectoryFile
    # TODO add fchdir too
    async def chdir(self, task: Task, path: Pointer) -> None:
        if task.fs != self:
            raise NamespaceMismatchError("can only chdir in a task with this FSInformation")
        self.cwd = rsyscall.near.DirectoryFile()
        await rsyscall.near.chdir(task.sysif, task.to_near_pointer(path))

    async def fchdir(self, task: Task, fd: FileDescriptor) -> None:
        if task.fs != self:
            raise NamespaceMismatchError("can only chdir in a task with this FSInformation")
        self.cwd = rsyscall.near.DirectoryFile()
        await rsyscall.near.fchdir(task.sysif, task.to_near_fd(fd))


@dataclass
class Root:
    pass

@dataclass
class CWD:
    pass

@dataclass
class Path:
    base: t.Union[Root, CWD, FileDescriptor]
    # The typical representation of a path as foo/bar/baz\0,
    # is really just a serialization of a list of components using / as the in-band separator.
    # We represent paths directly as the list they really are.
    components: t.List[bytes]
    def __post_init__(self) -> None:
        # Each component has no / in it and is non-zero length.
        for component in self.components:
            assert len(component) != 0
            assert b"/" not in component

    def _as_proc_path(self) -> bytes:
        """The path, using /proc to do dirfd-relative lookups

        This is not too portable - there are many situations where /proc might
        not be mounted. But if we have a dirfd-relative path, this is the only
        way to build an AF_UNIX sock address from the path or to pass the path
        to a subprocess.

        """
        pathdata = b"/".join(self.components)
        if isinstance(self.base, Root):
            ret = b"/" + pathdata
        elif isinstance(self.base, CWD):
            ret = pathdata
        elif isinstance(self.base, FileDescriptor):
            ret = b"/proc/self/fd/" + bytes(int(self.base)) + b"/" + pathdata
        else:
            raise Exception("invalid base type")
        return ret

    def __bytes__(self) -> bytes:
        return self._as_proc_path()

    def __str__(self) -> str:
        return bytes(self).decode()

# This is like a segment register, if a segment register was write-only. Then
# we'd need to maintain the knowledge of what the segment register was set to,
# outside the segment register itself. That's what we do here.
@dataclass
class Task:
    sysif: rsyscall.near.SyscallInterface
    fd_table: FDTable
    address_space: AddressSpace
    fs: FSInformation

    def to_near_pointer(self, pointer: Pointer) -> rsyscall.near.Pointer:
        return self.address_space.to_near(pointer)

    def to_near_fd(self, file_descriptor: FileDescriptor) -> rsyscall.near.FileDescriptor:
        return self.fd_table.to_near(file_descriptor)

    def to_near_mapping(self, mapping: MemoryMapping) -> rsyscall.near.MemoryMapping:
        return self.address_space.to_near_mapping(mapping)

# These are like the instructions in near, but they also do the appropriate dynamic check.
async def read(task: Task, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    assert task.fd_table == fd.fd_table
    assert task.address_space == buf.address_space
    return (await rsyscall.near.read(task.sysif, fd.near, buf.near, count))

async def write(task: Task, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    assert task.fd_table == fd.fd_table
    assert task.address_space == buf.address_space
    return (await rsyscall.near.write(task.sysif, fd.near, buf.near, count))

async def recv(task: Task, fd: FileDescriptor, buf: Pointer, count: int, flags: int) -> int:
    return (await rsyscall.near.recv(task.sysif, task.to_near_fd(fd), task.to_near_pointer(buf), count, flags))

async def close(task: Task, fd: FileDescriptor) -> None:
    await rsyscall.near.close(task.sysif, task.to_near_fd(fd))

async def sendmsg(task: Task, fd: FileDescriptor, msg: Pointer, flags: int) -> int:
    return (await rsyscall.near.sendmsg(task.sysif, task.to_near_fd(fd), task.to_near_pointer(msg), flags))

async def recvmsg(task: Task, fd: FileDescriptor, msg: Pointer, flags: int) -> int:
    return (await rsyscall.near.recvmsg(task.sysif, task.to_near_fd(fd), task.to_near_pointer(msg), flags))

async def dup3(task: Task, oldfd: FileDescriptor, newfd: FileDescriptor, flags: int) -> None:
    await rsyscall.near.dup3(task.sysif, task.to_near_fd(oldfd), task.to_near_fd(newfd), flags)

async def accept4(task: Task, sockfd: FileDescriptor,
                  addr: t.Optional[Pointer], addrlen: t.Optional[Pointer], flags: int) -> int:
    if addr is None:
        addr = 0 # type: ignore
    if addrlen is None:
        addrlen = 0 # type: ignore
    return (await rsyscall.near.accept4(task.sysif, task.to_near_fd(sockfd),
                                        task.to_near_pointer(addr) if addr else None,
                                        task.to_near_pointer(addrlen) if addrlen else None,
                                        flags))

async def memfd_create(task: Task, name: Pointer, flags: int) -> FileDescriptor:
    ret = await rsyscall.near.memfd_create(task.sysif, task.to_near_pointer(name), flags)
    return FileDescriptor(task.fd_table, ret)

async def ftruncate(task: Task, fd: FileDescriptor, length: int) -> None:
    await rsyscall.near.ftruncate(task.sysif, task.to_near_fd(fd), length)

async def mmap(task: Task, length: int, prot: int, flags: int,
               addr: t.Optional[Pointer]=None, 
               fd: t.Optional[FileDescriptor]=None, offset: int=0) -> MemoryMapping:
    ret = await rsyscall.near.mmap(task.sysif, length, prot, flags,
                                   task.to_near_pointer(addr) if addr else None,
                                   task.to_near_fd(fd) if fd else None,
                                   offset)
    return MemoryMapping(task.address_space, ret)

async def munmap(task: Task, mapping: MemoryMapping) -> None:
    await rsyscall.near.munmap(task.sysif, task.to_near_mapping(mapping))

async def set_tid_address(task: Task, ptr: Pointer) -> None:
    await rsyscall.near.set_tid_address(task.sysif, task.to_near_pointer(ptr))

async def set_robust_list(task: Task, head: Pointer, len: int) -> None:
    await rsyscall.near.set_robust_list(task.sysif, task.to_near_pointer(head), len)

async def getdents64(task: Task, fd: FileDescriptor, dirp: Pointer, count: int) -> int:
    return (await rsyscall.near.getdents64(task.sysif, task.to_near_fd(fd), task.to_near_pointer(dirp), count))

async def epoll_ctl(task: Task, epfd: FileDescriptor, op: rsyscall.near.EpollCtlOp,
                    fd: FileDescriptor, event: t.Optional[Pointer]=None) -> None:
    await rsyscall.near.epoll_ctl(task.sysif, task.to_near_fd(epfd), op, task.to_near_fd(fd),
                                  task.to_near_pointer(event) if event else None)
