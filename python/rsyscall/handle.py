from __future__ import annotations
from dataclasses import dataclass, field
import copy
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import gc
import rsyscall.far
import rsyscall.near
import trio
import os
import typing as t
import logging
logger = logging.getLogger(__name__)

# This is like a far pointer plus a segment register.
# It means that, as long as it doesn't throw an exception,
# we should be able to access the object behind this pointer.
# I'll call it... an active pointer.
# Aha! No, this is something with a precise name, in fact.
# This is... a handle.
# In the sense of classic Mac OS/PalmOS/16-bit Windows memory management.
# It is useful for several reasons:

# 1. When a task changes segments through unshare, existing handles
# associated with that task can be updated to contain far pointers
# which point to the same resources in the new segment. Note that the
# near pointers are unchanged when we use unshare to change segments,
# because unshare makes a copy of the old segment.

# 2. When a task changes segments through setns, existing handles
# associated with that task can be invalidated, as they are no longer
# usable in the new namespace. New handles for the task in the new
# namespace either have to be created from pre-existing handles held
# by other tasks in the new namespace, or bootstrapped from scratch.

# 3. When the last remaining valid handle referencing a specific far
# pointer is invalidated, we can close that far pointer using the task
# in that handle.

# 4. [Future work] Handles can be automatically invalidated on
# __del__; if the handle is the last remaining valid one, the close
# action mentioned above would be added to a queue and performed
# asynchronously by a periodic garbage collection coroutine. This
# queue would be flushed whenever a task changes segments or exits.

# 5. Instead of passing both a task and a far pointer as two arguments
# to a function, a handle (which contains both) can be passed, which
# is much more convenient.

# We don't want elementwise equality, because each instance of this
# should be treated as a separate reference to the file descriptor;
# only if all the instances are invalid can we close the fd.
@dataclass(eq=False)
class FileDescriptor:
    task: Task
    near: rsyscall.near.FileDescriptor
    valid: bool = True

    def validate(self) -> None:
        if not self.valid:
            raise Exception("handle is no longer valid")

    def check_is_for(self, task: Task) -> None:
        self.validate()
        if self.task != task:
            raise Exception("this file descriptor is for task", self.task, "not", task)
    
    @property
    def far(self) -> rsyscall.far.FileDescriptor:
        # TODO delete this property, we should go through handle helper methods
        # only, which don't check the fd table.
        # I think the only ill effect of using the "far" property is that
        # exceptions will be erroneously thrown if you use the resulting "far"
        # fd at the same time as an unshare is happening; no actual correctness
        # problems result, and the syscall would be fine if the exception wasn't
        # thrown.
        self.validate()
        return rsyscall.far.FileDescriptor(self.task.fd_table, self.near)

    async def invalidate(self) -> None:
        if self.valid:
            self.valid = False
            handles = self._remove_from_tracking()
            if len(handles) == 0:
                # we were the last handle for this fd, we should close it
                logging.debug("invalidating %s, no handles remaining, closing", self)
                await rsyscall.near.close(self.task.sysif, self.near)
            else:
                logging.debug("invalidating %s, handles remaining: %s", self, handles)

    def _remove_from_tracking(self) -> t.List[FileDescriptor]:
        self.task.fd_handles.remove(self)
        handles = fd_table_to_near_to_handles[self.task.fd_table][self.near]
        handles.remove(self)
        return handles

    def _invalidate_all_existing_handles(self) -> None:
        for handle in fd_table_to_near_to_handles[self.task.fd_table][self.near]:
            handle.valid = False
        del fd_table_to_near_to_handles[self.task.fd_table][self.near]

    def __del__(self) -> None:
        if self.valid:
            if len(self._remove_from_tracking()) == 0:
                logging.debug("leaked fd: %s", self)

    def __str__(self) -> str:
        return f"FD({self.task}, {self.near.number})"

    def __repr__(self) -> str:
        return f"FD({self.task}, {self.near.number}, valid={self.valid})"

    # should I just take handle.Pointers instead of near or far stuff? hmm.
    # should I really require ownership in this way?
    # well, the invalidation needs to work.
    # oh hmm! if the pointer comes from another task, how does that work?
    # so I'll take far Pointers, and Union[handle.FileDescriptor, far.FileDescriptor]
    async def read(self, buf: rsyscall.far.Pointer, count: int) -> int:
        self.validate()
        return (await rsyscall.near.read(self.task.sysif, self.near,
                                         self.task.to_near_pointer(buf), count))

    async def write(self, buf: rsyscall.far.Pointer, count: int) -> int:
        self.validate()
        return (await rsyscall.near.write(self.task.sysif, self.near,
                                          self.task.to_near_pointer(buf), count))

    async def ftruncate(self, length: int) -> None:
        self.validate()
        await rsyscall.near.ftruncate(self.task.sysif, self.near, length)

    async def mmap(self, length: int, prot: int, flags: int,
                   addr: t.Optional[rsyscall.far.Pointer]=None, offset: int=0,
    ) -> rsyscall.far.MemoryMapping:
        self.validate()
        ret = await rsyscall.near.mmap(self.task.sysif, length, prot, flags,
                                       self.task.to_near_pointer(addr) if addr else None,
                                       self.near, offset)
        return rsyscall.far.MemoryMapping(self.task.address_space, ret)

    # oldfd has to be a valid file descriptor. newfd is not, technically, required to be
    # open, but that's the best practice for avoiding races, so we require it anyway here.
    async def dup3(self, newfd: FileDescriptor, flags: int) -> FileDescriptor:
        self.validate()
        newfd_near = self.task.to_near_fd(newfd.far)
        # we take responsibility here for closing newfd (which we're doing through dup3)
        newfd._invalidate_all_existing_handles()
        await rsyscall.near.dup3(self.task.sysif, self.near, newfd_near, flags)
        return self.task.make_fd_handle(newfd_near)

    async def fcntl(self, cmd: int, arg: t.Optional[int]=None) -> int:
        self.validate()
        return (await rsyscall.near.fcntl(self.task.sysif, self.near, cmd, arg))

    async def setns(self, nstype: int) -> None:
        self.validate()
        await rsyscall.near.setns(self.task.sysif, self.near, nstype)

@dataclass
class Root:
    file: rsyscall.near.DirectoryFile
    task: Task

    def validate(self) -> None:
        if self.file is not self.task.fs.root:
            raise Exception("root directory mismatch", self.file, self.task.fs.root)

@dataclass
class CWD:
    file: rsyscall.near.DirectoryFile
    task: Task

    def validate(self) -> None:
        if self.file is not self.task.fs.cwd:
            raise Exception("current working directory mismatch", self.file, self.task.fs.cwd)

@dataclass
class Path:
    base: t.Union[Root, CWD, FileDescriptor]
    components: t.List[bytes]

    @property
    def far(self) -> rsyscall.far.Path:
        base = self.base
        if isinstance(base, Root):
            base.validate()
            return rsyscall.far.Path(rsyscall.far.Root(), self.components)
        elif isinstance(base, CWD):
            base.validate()
            return rsyscall.far.Path(rsyscall.far.CWD(), self.components)
        elif isinstance(base, FileDescriptor):
            return rsyscall.far.Path(base.far, self.components)
        else:
            raise Exception("bad path base type", base, type(base))

    def split(self) -> t.Tuple[Path, bytes]:
        return Path(self.base, self.components[:-1]), self.components[-1]

    def __truediv__(self, path_element: t.Union[str, bytes]) -> Path:
        element: bytes = os.fsencode(path_element)
        if b"/" in element:
            raise Exception("no / allowed in path elements, do it one by one")
        return Path(self.base, self.components+[element])

    def __bytes__(self) -> bytes:
        return bytes(self.far)

    def __str__(self) -> str:
        return str(self.far)

fd_table_to_near_to_handles: t.Dict[rsyscall.far.FDTable, t.Dict[rsyscall.near.FileDescriptor, t.List[FileDescriptor]]] = {}

class Task(rsyscall.far.Task):
    # work around breakage in mypy - it doesn't understand dataclass inheritance
    # TODO delete this
    def __init__(self,
                 sysif: rsyscall.near.SyscallInterface,
                 process: rsyscall.far.Process,
                 fd_table: rsyscall.far.FDTable,
                 address_space: rsyscall.far.AddressSpace,
                 fs: rsyscall.far.FSInformation
    ) -> None:
        self.sysif = sysif
        self.process = process
        self.fd_table = fd_table
        self.address_space = address_space
        self.fs = fs
        self.fd_handles: t.List[FileDescriptor] = []
        fd_table_to_near_to_handles.setdefault(self.fd_table, {})

    def make_path_from_bytes(self, path: bytes) -> Path:
        if path.startswith(b"/"):
            path = path[1:]
            if len(path) == 0:
                return Path(Root(self.fs.root, self), [])
            else:
                return Path(Root(self.fs.root, self), path.split(b"/"))
        else:
            return Path(CWD(self.fs.cwd, self), path.split(b"/"))

    def make_path_handle(self, path: Path) -> Path:
        base = path.base
        if isinstance(base, Root):
            if base.file is not self.fs.root:
                raise Exception("root directory mismatch", base.file, self.fs.root)
            return Path(Root(base.file, self), path.components)
        elif isinstance(base, CWD):
            if base.file is not self.fs.cwd:
                raise Exception("current working directory mismatch", base.file, self.fs.cwd)
            return Path(CWD(base.file, self), path.components)
        elif isinstance(base, FileDescriptor):
            return Path(self.make_fd_handle(base), path.components)
        else:
            raise Exception("bad path base type", base, type(base))

    def make_fd_handle(self, fd: t.Union[rsyscall.near.FileDescriptor,
                                         rsyscall.far.FileDescriptor,
                                         FileDescriptor]) -> FileDescriptor:
        if isinstance(fd, rsyscall.near.FileDescriptor):
            near = fd
        elif isinstance(fd, rsyscall.far.FileDescriptor):
            near = self.to_near_fd(fd)
        elif isinstance(fd, FileDescriptor):
            near = self.to_near_fd(fd.far)
        else:
            raise Exception("bad fd type", fd, type(fd))
        handle = FileDescriptor(self, near)
        logging.debug("made handle: %s", self)
        self.fd_handles.append(handle)
        fd_table_to_near_to_handles[self.fd_table].setdefault(near, []).append(handle)
        return handle

    async def unshare_files(self, do_unshare: t.Callable[[
            # fds to close in the old space
            t.List[rsyscall.near.FileDescriptor],
            # fds to copy into the new space
            t.List[rsyscall.near.FileDescriptor]
    ], t.Awaitable[None]]) -> None:
        old_fd_table = self.fd_table
        new_fd_table = rsyscall.far.FDTable(self.sysif.identifier_process.id)
        # force a garbage collection to improve efficiency
        gc.collect()
        new_near_to_handles: t.Dict[rsyscall.near.FileDescriptor, t.List[FileDescriptor]] = {}
        fd_table_to_near_to_handles[new_fd_table] = new_near_to_handles
        for handle in self.fd_handles:
            new_near_to_handles.setdefault(handle.near, []).append(handle)
        self.fd_table = new_fd_table
        old_near_to_handles = fd_table_to_near_to_handles[old_fd_table]
        snapshot_old_near_to_handles: t.Dict[rsyscall.near.FileDescriptor, t.List[FileDescriptor]] = {}
        for key in old_near_to_handles:
            snapshot_old_near_to_handles[key] = [fd for fd in old_near_to_handles[key]]
        needs_close: t.List[rsyscall.near.FileDescriptor] = []
        for handle in self.fd_handles:
            near = handle.near
            snapshot_old_near_to_handles[near].remove(handle)
            # If the list is empty, it means the only handles for this fd in the old fd
            # table are our own, and we therefore want to close this fd. No further
            # handles for this fd can be created, even while we are asynchronously calling
            # unshare, because no-one can make a new handle from one of ours, because we
            # changed our Task.fd_table to point to a new fd table.
            if len(snapshot_old_near_to_handles[near]) == 0:
                needs_close.append(near)
        await do_unshare(needs_close, [fd.near for fd in self.fd_handles])
        # We can only remove our handles from the handle lists after the unshare is done
        # and the fds are safely copied, because otherwise someone else running GC on the
        # old fd table would close our fds when they notice there are no more handles.
        for handle in self.fd_handles:
            old_near_to_handles[handle.near].remove(handle)

    async def unshare_fs(self) -> None:
        old_fs = self.fs
        new_fs = rsyscall.far.FSInformation(self.sysif.identifier_process.id,
                                            old_fs.root, old_fs.cwd)
        self.fs = new_fs
        try:
            await rsyscall.near.unshare(self.sysif, rsyscall.near.UnshareFlag.FS)
        except:
            self.fs = old_fs

    async def unshare_user(self) -> None:
        # unsharing the user namespace implicitly unshares CLONE_FS
        await self.unshare_fs()
        await rsyscall.near.unshare(self.sysif, rsyscall.near.UnshareFlag.NEWUSER)

    async def setns_user(self, fd: FileDescriptor) -> None:
        fd.check_is_for(self)
        # can't setns to a user namespace while sharing CLONE_FS
        await self.unshare_fs()
        await fd.setns(rsyscall.near.UnshareFlag.NEWUSER)

@dataclass
class Pipe:
    read: FileDescriptor
    write: FileDescriptor

@dataclass
class MemoryMapping:
    task: rsyscall.far.Task
    far: rsyscall.far.MemoryMapping

    async def munmap(self) -> None:
        await rsyscall.far.munmap(self.task, self.far)

