from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass, field
import copy
import fcntl
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import gc
import rsyscall.far
import rsyscall.near
import trio
import os
import typing as t
import logging
import contextlib
logger = logging.getLogger(__name__)

from rsyscall.sys.socket import AF, SOCK
from rsyscall.sched import UnshareFlag
from rsyscall.struct import T_serializable
from rsyscall.signal import Sigaction, Sigset, Signals

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

    async def invalidate(self) -> bool:
        """Invalidate this reference to this file descriptor

        Returns true if we remove the last reference, and close the FD.

        """
        if self.valid:
            self.valid = False
            handles = self._remove_from_tracking()
            if len(handles) == 0:
                # we were the last handle for this fd, we should close it
                logger.debug("invalidating %s, no handles remaining, closing", self)
                await rsyscall.near.close(self.task.sysif, self.near)
                return True
            else:
                logger.debug("invalidating %s, handles remaining: %s", self, handles)
                return False
        return False

    async def close(self) -> None:
        if not self.is_only_handle():
            raise Exception("can't close this fd, there are handles besides this one to it")
        if not self.valid:
            raise Exception("can't close an invalid FD handle")
        closed = await self.invalidate()
        if not closed:
            raise Exception("for some reason, the fd wasn't closed; "
                            "maybe some race condition where there are still handles left around?")

    def for_task(self, task: Task) -> FileDescriptor:
        return task.make_fd_handle(self)

    @contextlib.asynccontextmanager
    async def borrow(self, task: Task) -> t.AsyncGenerator[FileDescriptor, None]:
        if self.task == task:
            yield self
        else:
            borrowed = self.for_task(task)
            try:
                yield borrowed
            finally:
                await borrowed.invalidate()

    def maybe_copy(self, task: Task) -> FileDescriptor:
        """Copy this file descriptor into this task, if it isn't already in there.

        The immediate use case for this is when we're passed some FD handle and some task to use for
        some purpose, and we're taking ownership of the task. If the FD handle is already in the
        task, we don't need to copy it, since we necessarily are taking ownership of it; but if the
        FD handle is in some other task, then we do need to copy it.

        More concretely, that situation happens if we're passed a FD handle and a thread and we're
        going to exec in the thread. If we copy the FD handle unnecessarily, disable_cloexec won't
        work because there will be multiple FD handles.

        """
        if self.task == task:
            return self
        else:
            return self.for_task(task)

    def move(self, task: Task) -> FileDescriptor:
        """This is an optimized version of borrowing then invalidating

        We know that invalidate won't be removing the last handle and
        need to close the fd, so we don't need to do the invalidate as
        async. We assert to make sure this is true.

        """
        new = self.for_task(task)
        self.valid = False
        handles = self._remove_from_tracking()
        if len(handles) == 0:
            raise Exception("We just made handle B from handle A, "
                            "so we know there are at least two handles; "
                            "but after removing handle A, there are no handles left. Huh?")
        return new

    def _get_global_handles(self) -> t.List[FileDescriptor]:
        return fd_table_to_near_to_handles[self.task.fd_table][self.near]

    def is_only_handle(self) -> bool:
        self.validate()
        return len(self._get_global_handles()) == 1

    def _remove_from_tracking(self) -> t.List[FileDescriptor]:
        self.task.fd_handles.remove(self)
        handles = self._get_global_handles()
        handles.remove(self)
        return handles

    def _invalidate_all_existing_handles(self) -> None:
        for handle in fd_table_to_near_to_handles[self.task.fd_table][self.near]:
            handle.valid = False
        del fd_table_to_near_to_handles[self.task.fd_table][self.near]

    def __del__(self) -> None:
        if self.valid:
            if len(self._remove_from_tracking()) == 0:
                logger.debug("leaked fd: %s", self)

    def __str__(self) -> str:
        return f"FD({self.task}, {self.near.number})"

    def __repr__(self) -> str:
        return f"FD({self.task}, {self.near.number}, valid={self.valid})"

    def as_proc_path(self) -> Path:
        pid = self.task.process.near.id
        num = self.near.number
        return self.task.make_path_from_bytes(f"/proc/{pid}/fd/{num}".encode())

    async def disable_cloexec(self) -> None:
        self.validate()
        if not self.is_only_handle():
            raise Exception("shouldn't disable cloexec when there are multiple handles to this fd")
        await rsyscall.near.fcntl(self.task.sysif, self.near, fcntl.F_SETFD, 0)

    async def as_argument(self) -> int:
        await self.disable_cloexec()
        return int(self.near)

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

    async def pread(self, buf: rsyscall.far.Pointer, count: int, offset: int) -> int:
        self.validate()
        return (await rsyscall.near.pread(self.task.sysif, self.near,
                                          self.task.to_near_pointer(buf), count, offset))

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
        if not newfd.is_only_handle():
            raise Exception("can't dup over newfd, there are more handles to it than just ours")
        newfd_near = self.task.to_near_fd(newfd.far)
        # we take responsibility here for closing newfd (which we're doing through dup3)
        newfd._invalidate_all_existing_handles()
        await rsyscall.near.dup3(self.task.sysif, self.near, newfd_near, flags)
        return self.task.make_fd_handle(newfd_near)

    async def fcntl(self, cmd: int, arg: t.Optional[int]=None) -> int:
        self.validate()
        return (await rsyscall.near.fcntl(self.task.sysif, self.near, cmd, arg))

    async def ioctl(self, request: int, arg: Pointer) -> int:
        self.validate()
        arg.validate()
        return (await rsyscall.near.ioctl(self.task.sysif, self.near, request, arg.near))

    async def setns(self, nstype: int) -> None:
        self.validate()
        await rsyscall.near.setns(self.task.sysif, self.near, nstype)

    async def epoll_wait(self, events: rsyscall.far.Pointer, maxevents: int, timeout: int) -> int:
        self.validate()
        return (await rsyscall.near.epoll_wait(self.task.sysif, self.near,
                                               self.task.to_near_pointer(events), maxevents,
                                               timeout))

    async def inotify_add_watch(self, pathname: rsyscall.far.Pointer, mask: int) -> rsyscall.near.WatchDescriptor:
        self.validate()
        return (await rsyscall.near.inotify_add_watch(
            self.task.sysif, self.near, self.task.to_near_pointer(pathname), mask))

    async def inotify_rm_watch(self, wd: rsyscall.near.WatchDescriptor) -> None:
        self.validate()
        await rsyscall.near.inotify_rm_watch(self.task.sysif, self.near, wd)

    async def bind(self, addr: Pointer) -> None:
        self.validate()
        async with addr.borrow(self.task) as addr:
            await rsyscall.near.bind(self.task.sysif, self.near, addr.near, addr.bytesize())

    async def listen(self, backlog: int) -> None:
        self.validate()
        await rsyscall.near.listen(self.task.sysif, self.near, backlog)

    async def setsockopt(self, level: int, optname: int, optval: Pointer) -> None:
        self.validate()
        await rsyscall.near.setsockopt(self.task.sysif, self.near, level, optname, optval.near, optval.bytesize())

# With handle.Pointer, we know the length of the region of memory
# we're pointing to.  If we didn't know that, then this pointer
# wouldn't make any sense as an owning handle that can be passed
# around.  And as a further development, we don't just know the size
# of the region of memory, but instead we actually know the "type" of
# the region of memory; the struct that will be written there. The
# size is merely a consequence of the type of the memory region, so
# there's no point in having something that knows the size but not the
# type.
@dataclass(eq=False)
class Pointer(t.Generic[T_serializable]):
    task: Task
    data_cls: t.Type[T_serializable]
    near: rsyscall.near.Pointer
    size: int
    to_free: t.Callable[[], None]
    valid: bool = True
    
    @property
    def far(self) -> rsyscall.far.Pointer:
        # TODO delete this property
        self.validate()
        return rsyscall.far.Pointer(self.task.address_space, self.near)

    @contextlib.asynccontextmanager
    async def borrow(self, task: Task) -> t.AsyncGenerator[Pointer, None]:
        # actual tracking of pointer references is not yet implemented
        self.validate()
        yield self

    def bytesize(self) -> int:
        return self.size

    def validate(self) -> None:
        if not self.valid:
            raise Exception("handle is no longer valid")

    def free(self) -> None:
        if self.valid:
            self.valid = False
            self.to_free() # type: ignore

    def __del__(self) -> None:
        if self.valid:
            self.valid = False
            self.to_free() # type: ignore

    def __enter__(self) -> Pointer:
        return self

    def __exit__(self) -> None:
        if self.valid:
            self.valid = False
            self.to_free() # type: ignore

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

T_path = t.TypeVar('T_path', bound="Path")
@dataclass
class Path(rsyscall.far.PathLike):
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
        return type(self)(self.base, self.components+[element])

    @t.overload
    def __getitem__(self, i: int) -> bytes: ...
    @t.overload
    def __getitem__(self: T_path, s: slice) -> T_path: ...

    def __getitem__(self: T_path, s: t.Union[int, slice]) -> t.Union[bytes, T_path]:
        if isinstance(s, slice):
            return type(self)(self.base, self.components[s])
        else:
            return self.components[s]

    def __fspath__(self) -> str:
        return self.far.__fspath__()

fd_table_to_near_to_handles: t.Dict[rsyscall.far.FDTable, t.Dict[rsyscall.near.FileDescriptor, t.List[FileDescriptor]]] = {}

class Task(rsyscall.far.Task):
    # work around breakage in mypy - it doesn't understand dataclass inheritance
    # TODO delete this
    def __init__(self,
                 sysif: rsyscall.near.SyscallInterface,
                 process: rsyscall.far.Process,
                 fd_table: rsyscall.far.FDTable,
                 address_space: rsyscall.far.AddressSpace,
                 fs: rsyscall.far.FSInformation,
                 pidns: rsyscall.far.PidNamespace,
                 netns: rsyscall.far.NetNamespace,
    ) -> None:
        self.sysif = sysif
        self.process = process
        self.fd_table = fd_table
        self.address_space = address_space
        self.fs = fs
        self.pidns = pidns
        self.netns = netns
        self.fd_handles: t.List[FileDescriptor] = []
        fd_table_to_near_to_handles.setdefault(self.fd_table, {})

    @property
    def root(self) -> Root:
        return Root(self.fs.root, self)

    @property
    def cwd(self) -> CWD:
        return CWD(self.fs.cwd, self)

    def make_path_from_bytes(self, path: t.Union[str, bytes]) -> Path:
        path = os.fsencode(path)
        if path.startswith(b"/"):
            path = path[1:]
            if len(path) == 0:
                return Path(self.root, [])
            else:
                return Path(self.root, path.split(b"/"))
        else:
            return Path(self.cwd, path.split(b"/"))

    def make_path_handle(self, path: Path) -> Path:
        base = path.base
        if isinstance(base, Root):
            if base.file is not self.fs.root:
                raise Exception("root directory mismatch", base.file, self.fs.root)
            return Path(self.root, path.components)
        elif isinstance(base, CWD):
            if base.file is not self.fs.cwd:
                raise Exception("current working directory mismatch", base.file, self.fs.cwd)
            return Path(self.cwd, path.components)
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
        logger.debug("made handle: %s", self)
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
            await rsyscall.near.unshare(self.sysif, UnshareFlag.FS)
        except:
            self.fs = old_fs

    async def unshare_user(self) -> None:
        # unsharing the user namespace implicitly unshares CLONE_FS
        await self.unshare_fs()
        await rsyscall.near.unshare(self.sysif, UnshareFlag.NEWUSER)

    async def unshare_net(self) -> None:
        await rsyscall.near.unshare(self.sysif, UnshareFlag.NEWNET)

    async def setns_user(self, fd: FileDescriptor) -> None:
        async with fd.borrow(self) as fd:
            # can't setns to a user namespace while sharing CLONE_FS
            await self.unshare_fs()
            await fd.setns(UnshareFlag.NEWUSER)

    async def setns_net(self, fd: FileDescriptor) -> None:
        async with fd.borrow(self) as fd:
            await fd.setns(UnshareFlag.NEWNET)

    async def socket(self, family: AF, type: SOCK, protocol: int=0, cloexec=True) -> FileDescriptor:
        if cloexec:
            type |= lib.SOCK_CLOEXEC
        sockfd = await rsyscall.near.socket(self.sysif, family, type, protocol)
        return self.make_fd_handle(sockfd)

    async def capset(self, hdrp: Pointer, datap: Pointer) -> None:
        async with hdrp.borrow(self) as hdrp:
            async with datap.borrow(self) as datap:
                await rsyscall.near.capset(self.sysif, hdrp.near, datap.near)

    async def capget(self, hdrp: Pointer, datap: Pointer) -> None:
        async with hdrp.borrow(self) as hdrp:
            async with datap.borrow(self) as datap:
                await rsyscall.near.capget(self.sysif, hdrp.near, datap.near)

    async def rt_sigaction(self, signum: Signals,
                           act: t.Optional[Pointer[Sigaction]],
                           oldact: t.Optional[Pointer[Sigaction]]) -> None:
        async with contextlib.AsyncExitStack() as stack:
            if act:
                act = await stack.enter_async_context(act.borrow(self))
            if oldact:
                oldact = await stack.enter_async_context(oldact.borrow(self))
            # rt_sigaction takes the size of the sigset, not the size of the sigaction;
            # and sigset is a fixed size.
            await rsyscall.near.rt_sigaction(self.sysif, signum,
                                             act.near if act else None,
                                             oldact.near if oldact else None,
                                             Sigset.sizeof())

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

