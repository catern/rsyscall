from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass, field
import copy
import rsyscall.raw_syscalls as raw_syscall
import gc
import rsyscall.far
import rsyscall.near
from rsyscall.near import File
import trio
import os
import typing as t
import logging
import contextlib
import abc
import rsyscall.memint as memint
logger = logging.getLogger(__name__)

from rsyscall.sys.socket import AF, SOCK, SOL, SCM, Address, Socklen, SendmsgFlags, RecvmsgFlags, MsghdrFlags
from rsyscall.sched import UnshareFlag, CLONE
from rsyscall.struct import Serializer, HasSerializer, FixedSize, Serializable, Int32, Struct
from rsyscall.signal import Sigaction, Sigset, Signals, SigprocmaskHow, Siginfo
from rsyscall.fcntl import AT, F, O
from rsyscall.path import Path
from rsyscall.unistd import SEEK
from rsyscall.sys.epoll import EpollFlag, EpollCtlOp, EpollEvent, EpollEventList
from rsyscall.linux.dirent import DirentList
from rsyscall.sys.inotify import InotifyFlag, IN
from rsyscall.sys.memfd import MFD
from rsyscall.sys.wait import W
from rsyscall.sys.mman import MAP, PROT

class AllocationInterface:
    @abc.abstractmethod
    def offset(self) -> int: ...
    @abc.abstractmethod
    def size(self) -> int: ...
    @abc.abstractmethod
    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]: ...
    @abc.abstractmethod
    def merge(self, other: AllocationInterface) -> AllocationInterface: ...
    @abc.abstractmethod
    def free(self) -> None: ...

# With handle.Pointer, we know the length of the region of memory
# we're pointing to.  If we didn't know that, then this pointer
# wouldn't make any sense as an owning handle that can be passed
# around.  And as a further development, we don't just know the size
# of the region of memory, but instead we actually know the "type" of
# the region of memory; the struct that will be written there. The
# size is merely a consequence of the type of the memory region, so
# there's no point in having something that knows the size but not the
# type.
T = t.TypeVar('T')
U = t.TypeVar('U')
T_pointer = t.TypeVar('T_pointer', bound='Pointer')
@dataclass(eq=False)
class Pointer(t.Generic[T]):
    mapping: MemoryMapping
    transport: memint.MemoryGateway
    serializer: Serializer[T]
    allocation: AllocationInterface
    valid: bool = True

    @property
    def near(self) -> rsyscall.near.Pointer:
        # TODO hmm should maybe validate that this fits in the bounds of the mapping I guess
        return self.mapping.near.as_pointer() + self.allocation.offset()

    def bytesize(self) -> int:
        return self.allocation.size()

    @property
    def far(self) -> rsyscall.far.Pointer:
        # TODO delete this property
        self.validate()
        return rsyscall.far.Pointer(self.mapping.task.address_space, self.near)

    @contextlib.asynccontextmanager
    async def borrow(self, task: Task) -> t.AsyncGenerator[Pointer, None]:
        # TODO actual tracking of pointer references is not yet implemented
        self.validate()
        if task.address_space != self.mapping.task.address_space:
            raise Exception("pointer is in different address space")
        yield self

    def _with_alloc(self: T_pointer, allocation: AllocationInterface) -> T_pointer:
        # TODO how can I do this statically?
        if type(self) is not Pointer:
            raise Exception("subclasses of Pointer must override _with_alloc")
        return type(self)(self.mapping, self.transport, self.serializer, allocation)

    def split(self: T_pointer, size: int) -> t.Tuple[T_pointer, T_pointer]:
        self.validate()
        # TODO uhhhh if split throws an exception... don't we need to free... or something...
        self.valid = False
        # TODO we should only allow split if we are the only reference to this allocation
        alloc1, alloc2 = self.allocation.split(size)
        first = self._with_alloc(alloc1)
        # TODO should degrade this pointer to raw bytes or something, or maybe no type at all
        second = self._with_alloc(alloc2)
        return first, second

    def merge(self: T_pointer, ptr: T_pointer) -> T_pointer:
        self.validate()
        ptr.validate()
        # TODO should assert that these two pointers both serialize the same thing
        # although they could be different types of serializers...
        self.valid = False
        # TODO we should only allow merge if we are the only reference to this allocation
        alloc = self.allocation.merge(ptr.allocation)
        return self._with_alloc(alloc)

    def validate(self) -> None:
        if not self.valid:
            raise Exception("handle is no longer valid")

    def free(self) -> None:
        if self.valid:
            self.valid = False
            self.allocation.free()

    def __del__(self) -> None:
        # This isn't strictly necessary because the allocation will free itself on __del__.
        # But, that will only happen when *all* pointers referring to the allocation are collected;
        # not just the valid one.
        # So, this ensures GC is a bit more prompt.
        self.free()

    def _wrote(self, data: T) -> WrittenPointer[T]:
        self.valid = False
        return WrittenPointer(self.mapping, self.transport, data, self.serializer, self.allocation)

    async def write(self, data: T) -> WrittenPointer[T]:
        self.validate()
        data_bytes = self.serializer.to_bytes(data)
        if len(data_bytes) > self.bytesize():
            raise Exception("data is too long", len(data_bytes),
                            "for this typed pointer of size", self.bytesize())
        await self.transport.write(self.far, data_bytes)
        return self._wrote(data)

    def split_from_end(self: T_pointer, size: int, alignment: int) -> t.Tuple[T_pointer, T_pointer]:
        extra_to_remove = (int(self.near) + size) % alignment
        return self.split(self.bytesize() - size - extra_to_remove)

    async def write_to_end(self, data: T, alignment: int) -> t.Tuple[Pointer[T], WrittenPointer[T]]:
        """Write a piece of data to the end of the range of this pointer

        Splits the pointer, and returns both parts.  This function is only useful for preparing
        stacks. Would be nice to figure out either a more generic way to prep stacks, or to figure
        out more things that write_to_end could be used for.

        """
        data_bytes = self.serializer.to_bytes(data)
        rest, write_buf = self.split_from_end(len(data_bytes), alignment)
        written = await write_buf.write(data)
        return rest, written

    async def read(self) -> T:
        self.validate()
        data = await self.transport.read(self.far, self.bytesize())
        return self.serializer.from_bytes(data)

    def _reinterpret(self, serializer: Serializer[U]) -> Pointer[U]:
        # TODO how can we check to make sure we don't reinterpret in wacky ways?
        # maybe we should only be able to reinterpret in ways that are allowed by the serializer?
        # so maybe it's a method on the Serializer? cast_to(Type)?
        self.validate()
        self.valid = False
        return Pointer(self.mapping, self.transport, serializer, self.allocation)

    def __enter__(self) -> Pointer:
        return self

    def __exit__(self, *args) -> None:
        self.free()

class WrittenPointer(Pointer[T]):
    def __init__(self,
                 mapping: MemoryMapping,
                 transport: memint.MemoryGateway,
                 data: T,
                 serializer: Serializer[T],
                 allocation: AllocationInterface,
    ) -> None:
        super().__init__(mapping, transport, serializer, allocation)
        self.data = data

    @property
    def value(self) -> T:
        # can't decide what to call this field
        return self.data

    def _with_alloc(self, allocation: AllocationInterface) -> WrittenPointer:
        if type(self) is not WrittenPointer:
            raise Exception("subclasses of WrittenPointer must override _with_alloc")
        return type(self)(self.mapping, self.transport, self.data, self.serializer, allocation)

# hmm. so what do we index the second bit with?
# allocationinterface? does that really make sense?
file_to_allocation_to_handles: t.Dict[File, t.Dict[AllocationInterface, t.List[Pointer]]] = {}

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
        return Path(f"/proc/{pid}/fd/{num}")

    def as_proc_self_path(self) -> Path:
        num = self.near.number
        return Path(f"/proc/self/fd/{num}")

    async def disable_cloexec(self) -> None:
        if not self.is_only_handle():
            raise Exception("shouldn't disable cloexec when there are multiple handles to this fd")
        await self.fcntl(F.SETFD, 0)

    async def as_argument(self) -> int:
        await self.disable_cloexec()
        return int(self.near)

    async def read(self, buf: T_pointer) -> t.Tuple[T_pointer, T_pointer]:
        self.validate()
        async with buf.borrow(self.task) as buf_b:
            ret = await rsyscall.near.read(self.task.sysif, self.near, buf_b.near, buf_b.bytesize())
            return buf.split(ret)

    async def write(self, buf: T_pointer) -> t.Tuple[T_pointer, T_pointer]:
        self.validate()
        async with buf.borrow(self.task) as buf_b:
            ret = await rsyscall.near.write(self.task.sysif, self.near, buf_b.near, buf_b.bytesize())
            return buf.split(ret)

    async def sendmsg(self, msg: WrittenPointer[SendMsghdr], flags: SendmsgFlags
    ) -> t.Tuple[IovecList, IovecList]:
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(msg.borrow(self.task))
            if msg.value.name:
                await stack.enter_async_context(msg.value.name.borrow(self.task))
            if msg.value.control:
                await stack.enter_async_context(msg.value.control.borrow(self.task))
                await msg.value.control.value.borrow_with(stack, self.task)
            await stack.enter_async_context(msg.value.iov.borrow(self.task))
            for iovec_elem in msg.value.iov.value:
                await stack.enter_async_context(iovec_elem.borrow(self.task))
            ret = await rsyscall.near.sendmsg(self.task.sysif, self.near, msg.near, flags)
        return msg.value.iov.value.split(ret)

    async def recvmsg(self, msg: WrittenPointer[RecvMsghdr], flags: RecvmsgFlags
    ) -> t.Tuple[IovecList, IovecList, Pointer[RecvMsghdrOut]]:
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(msg.borrow(self.task))
            if msg.value.name:
                await stack.enter_async_context(msg.value.name.borrow(self.task))
            if msg.value.control:
                await stack.enter_async_context(msg.value.control.borrow(self.task))
            await stack.enter_async_context(msg.value.iov.borrow(self.task))
            for iovec_elem in msg.value.iov.value:
                await stack.enter_async_context(iovec_elem.borrow(self.task))
            ret = await rsyscall.near.recvmsg(self.task.sysif, self.near, msg.near, flags)
        valid, invalid = msg.value.iov.value.split(ret)
        return valid, invalid, msg.value.to_out(msg)

    async def recv(self, buf: T_pointer, flags: int) -> t.Tuple[T_pointer, T_pointer]:
        self.validate()
        async with buf.borrow(self.task) as buf_b:
            ret = await rsyscall.near.recv(self.task.sysif, self.near, buf_b.near, buf_b.bytesize(), flags)
            return buf.split(ret)

    async def lseek(self, offset: int, whence: SEEK) -> int:
        self.validate()
        return (await rsyscall.near.lseek(self.task.sysif, self.near, offset, whence))

    async def ftruncate(self, length: int) -> None:
        self.validate()
        await rsyscall.near.ftruncate(self.task.sysif, self.near, length)

    async def mmap(self, length: int, prot: PROT, flags: MAP,
                   offset: int=0,
                   page_size: int=4096,
                   file: File=None,
    ) -> MemoryMapping:
        self.validate()
        if file is None:
            file = File()
        ret = await rsyscall.near.mmap(self.task.sysif, length, prot, flags,
                                       fd=self.near, offset=offset,
                                       page_size=page_size)
        return MemoryMapping(self.task, ret, file)

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

    T_pointer_eel = t.TypeVar('T_pointer_eel', bound='Pointer[EpollEventList]')
    async def epoll_wait(self, events: T_pointer_eel, timeout: int) -> t.Tuple[T_pointer_eel, T_pointer_eel]:
        self.validate()
        async with events.borrow(self.task) as events_b:
            num = await rsyscall.near.epoll_wait(
                self.task.sysif, self.near, events_b.near, events_b.bytesize()//EpollEvent.sizeof(), timeout)
            valid_size = num * EpollEvent.sizeof()
            return events.split(valid_size)

    async def epoll_ctl(self, op: EpollCtlOp, fd: FileDescriptor, event: t.Optional[Pointer[EpollEvent]]=None) -> None:
        self.validate()
        async with fd.borrow(self.task) as fd:
            if event is not None:
                if event.bytesize() < EpollEvent.sizeof():
                    raise Exception("pointer is too small", event.bytesize(), "to be an EpollEvent", EpollEvent.sizeof())
                async with event.borrow(self.task) as eventp:
                    return (await rsyscall.near.epoll_ctl(self.task.sysif, self.near, op, fd.near, eventp.near))
            else:
                return (await rsyscall.near.epoll_ctl(self.task.sysif, self.near, op, fd.near))

    async def inotify_add_watch(self, pathname: WrittenPointer[Path], mask: IN) -> rsyscall.near.WatchDescriptor:
        self.validate()
        async with pathname.borrow(self.task) as pathname_b:
            return (await rsyscall.near.inotify_add_watch(self.task.sysif, self.near, pathname_b.near, mask))

    async def inotify_rm_watch(self, wd: rsyscall.near.WatchDescriptor) -> None:
        self.validate()
        await rsyscall.near.inotify_rm_watch(self.task.sysif, self.near, wd)

    async def bind(self, addr: Pointer[Address]) -> None:
        self.validate()
        async with addr.borrow(self.task) as addr:
            await rsyscall.near.bind(self.task.sysif, self.near, addr.near, addr.bytesize())

    async def connect(self, addr: Pointer[Address]) -> None:
        self.validate()
        async with addr.borrow(self.task) as addr:
            await rsyscall.near.connect(self.task.sysif, self.near, addr.near, addr.bytesize())

    async def listen(self, backlog: int) -> None:
        self.validate()
        await rsyscall.near.listen(self.task.sysif, self.near, backlog)

    async def getsockopt(self, level: int, optname: int, optval: Pointer, optlen: WrittenPointer[Socklen]) -> None:
        self.validate()
        if optlen.data > optval.bytesize():
            raise ValueError("optlen contains", optlen.data,
                             "should contain the length of the opt buf", optval.bytesize())
        async with optval.borrow(self.task) as optval_b:
            async with optlen.borrow(self.task) as optlen_b:
                await rsyscall.near.getsockopt(self.task.sysif, self.near, level, optname, optval_b.near, optlen_b.near)

    async def setsockopt(self, level: int, optname: int, optval: Pointer) -> None:
        self.validate()
        async with optval.borrow(self.task) as optval_b:
            await rsyscall.near.setsockopt(self.task.sysif, self.near, level, optname, optval_b.near, optval_b.bytesize())

    async def getsockname(self, addr: Pointer, addrlen: WrittenPointer[Socklen]) -> None:
        self.validate()
        if addrlen.data > addr.bytesize():
            raise ValueError("addrlen contains", addrlen.data,
                             "should contain the length of the addr buf", addr.bytesize())
        async with addr.borrow(self.task) as addr_b:
            async with addrlen.borrow(self.task) as addrlen_b:
                await rsyscall.near.getsockname(self.task.sysif, self.near, addr_b.near, addrlen_b.near)

    async def getpeername(self, addr: Pointer, addrlen: WrittenPointer[Socklen]) -> None:
        self.validate()
        if addrlen.data > addr.bytesize():
            raise ValueError("addrlen contains", addrlen.data,
                             "should contain the length of the addr buf", addr.bytesize())
        async with addr.borrow(self.task) as addr_b:
            async with addrlen.borrow(self.task) as addrlen_b:
                await rsyscall.near.getpeername(self.task.sysif, self.near, addr_b.near, addrlen_b.near)

    @t.overload
    async def accept(self, flags: SOCK) -> FileDescriptor: ...
    @t.overload
    async def accept(self, flags: SOCK, addr: Pointer, addrlen: WrittenPointer[Socklen]) -> FileDescriptor: ...

    async def accept(self, flags: SOCK,
                     addr: t.Optional[Pointer]=None, addrlen: t.Optional[WrittenPointer[Socklen]]=None) -> FileDescriptor:
        self.validate()
        if addr is None:
            fd = await rsyscall.near.accept4(self.task.sysif, self.near, None, None, flags)
            return self.task.make_fd_handle(fd)
        else:
            if addrlen is None:
                raise ValueError("if you pass addr, you must also pass addrlen")
            if addrlen.data > addr.bytesize():
                raise ValueError("addrlen contains", addrlen.data,
                                 "should contain the length of the addr buf", addr.bytesize())
            async with addrlen.borrow(self.task) as addrlen_b:
                async with addr.borrow(self.task) as addr_b:
                    fd = await rsyscall.near.accept4(self.task.sysif, self.near, addr_b.near, addrlen_b.near, flags)
                    return self.task.make_fd_handle(fd)

    async def readlinkat(self, path: Pointer, buf: T_pointer) -> t.Tuple[T_pointer, T_pointer]:
        self.validate()
        async with path.borrow(self.task) as path:
            async with buf.borrow(self.task) as buf_b:
                ret = await rsyscall.near.readlinkat(self.task.sysif, self.near, path.near, buf_b.near, buf_b.bytesize())
                return buf.split(ret)

    T_pointer_dl = t.TypeVar('T_pointer_dl', bound='Pointer[DirentList]')
    async def getdents(self, dirp: T_pointer_dl) -> t.Tuple[T_pointer_dl, T_pointer_dl]:
        self.validate()
        async with dirp.borrow(self.task) as dirp_b:
            ret = await rsyscall.near.getdents64(self.task.sysif, self.near, dirp_b.near, dirp_b.bytesize())
            return dirp.split(ret)

    async def signalfd(self, mask: Pointer[Sigset], flags: int) -> None:
        self.validate()
        async with mask.borrow(self.task) as mask:
            await rsyscall.near.signalfd4(self.task.sysif, self.near, mask.near, mask.bytesize(), flags)

fd_table_to_near_to_handles: t.Dict[rsyscall.far.FDTable, t.Dict[rsyscall.near.FileDescriptor, t.List[FileDescriptor]]] = {}

class Task(rsyscall.far.Task):
    # work around breakage in mypy - it doesn't understand dataclass inheritance
    # TODO delete this
    def __init__(self,
                 sysif: rsyscall.near.SyscallInterface,
                 process: t.Union[rsyscall.near.Process, Process],
                 parent_task: t.Optional[Task],
                 fd_table: rsyscall.far.FDTable,
                 address_space: rsyscall.far.AddressSpace,
                 fs: rsyscall.far.FSInformation,
                 pidns: rsyscall.far.PidNamespace,
                 netns: rsyscall.far.NetNamespace,
    ) -> None:
        self.sysif = sysif
        if isinstance(process, Process):
            self.process = process
        else:
            self.process = Process(self, process)
        self.parent_task = parent_task
        self.fd_table = fd_table
        self.address_space = address_space
        self.fs = fs
        self.pidns = pidns
        self.netns = netns
        self.fd_handles: t.List[FileDescriptor] = []
        fd_table_to_near_to_handles.setdefault(self.fd_table, {})

    @property
    def root(self) -> Path:
        return Path('/')

    @property
    def cwd(self) -> Path:
        return Path('.')

    def make_path_from_bytes(self, path: t.Union[str, bytes]) -> Path:
        return Path(os.fsdecode(path))

    def make_path_handle(self, path: Path) -> Path:
        return path

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
        self.fs = rsyscall.far.FSInformation(self.sysif.identifier_process.id)
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

    async def sigaction(self, signum: Signals,
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

    async def open(self, ptr: WrittenPointer[Path], flags: int, mode=0o644) -> FileDescriptor:
        async with ptr.borrow(self) as ptr_b:
            fd = await rsyscall.near.openat(self.sysif, None, ptr_b.near, flags, mode)
            return self.make_fd_handle(fd)

    async def mkdir(self, ptr: WrittenPointer[Path], mode=0o644) -> None:
        async with ptr.borrow(self) as ptr_b:
            await rsyscall.near.mkdirat(self.sysif, None, ptr_b.near, mode)

    async def access(self, ptr: WrittenPointer[Path], mode: int, flags: int=0) -> None:
        async with ptr.borrow(self) as ptr_b:
            await rsyscall.near.faccessat(self.sysif, None, ptr_b.near, mode, flags)

    async def unlink(self, ptr: WrittenPointer[Path]) -> None:
        async with ptr.borrow(self) as ptr_b:
            await rsyscall.near.unlinkat(self.sysif, None, ptr_b.near, 0)

    async def rmdir(self, ptr: WrittenPointer[Path]) -> None:
        async with ptr.borrow(self) as ptr_b:
            await rsyscall.near.unlinkat(self.sysif, None, ptr_b.near, AT.REMOVEDIR)

    async def link(self, oldpath: WrittenPointer[Path], newpath: WrittenPointer[Path]) -> None:
        async with oldpath.borrow(self) as oldpath_b:
            async with newpath.borrow(self) as newpath_b:
                await rsyscall.near.linkat(self.sysif, None, oldpath_b.near, None, newpath_b.near, 0)

    async def rename(self, oldpath: WrittenPointer[Path], newpath: WrittenPointer[Path]) -> None:
        async with oldpath.borrow(self) as oldpath_b:
            async with newpath.borrow(self) as newpath_b:
                await rsyscall.near.renameat2(self.sysif, None, oldpath_b.near, None, newpath_b.near, 0)

    async def symlink(self, target: WrittenPointer, linkpath: WrittenPointer[Path]) -> None:
        async with target.borrow(self) as target_b:
            async with linkpath.borrow(self) as linkpath_b:
                await rsyscall.near.symlinkat(self.sysif, target_b.near, None, linkpath_b.near)

    async def chdir(self, path: WrittenPointer[Path]) -> None:
        async with path.borrow(self) as path_b:
            await rsyscall.near.chdir(self.sysif, path_b.near)

    async def fchdir(self, fd: FileDescriptor) -> None:
        async with fd.borrow(self) as fd:
            await rsyscall.near.fchdir(self.sysif, fd.near)

    async def readlink(self, path: WrittenPointer[Path], buf: T_pointer) -> t.Tuple[T_pointer, T_pointer]:
        async with path.borrow(self) as path_b:
            async with buf.borrow(self) as buf_b:
                ret = await rsyscall.near.readlinkat(self.sysif, None, path_b.near, buf_b.near, buf_b.bytesize())
                return buf.split(ret)

    async def signalfd(self, mask: Pointer[Sigset], flags: int) -> FileDescriptor:
        async with mask.borrow(self) as mask:
            fd = await rsyscall.near.signalfd4(self.sysif, None, mask.near, mask.bytesize(), flags)
            return self.make_fd_handle(fd)

    async def epoll_create(self, flags: EpollFlag) -> FileDescriptor:
        fd = await rsyscall.near.epoll_create(self.sysif, flags)
        return self.make_fd_handle(fd)

    async def inotify_init(self, flags: InotifyFlag) -> FileDescriptor:
        fd = await rsyscall.near.inotify_init(self.sysif, flags)
        return self.make_fd_handle(fd)

    async def memfd_create(self, name: WrittenPointer[Path], flags: MFD) -> FileDescriptor:
        async with name.borrow(self) as name_b:
            fd = await rsyscall.near.memfd_create(self.sysif, name_b.near, flags)
            return self.make_fd_handle(fd)

    async def waitid(self, options: W, infop: Pointer[Siginfo],
                     *, rusage: t.Optional[Pointer[Siginfo]]=None) -> None:
        async with infop.borrow(self) as infop_b:
            if rusage is None:
                await rsyscall.near.waitid(self.sysif, None, infop_b.near, options, None)
            else:
                async with rusage.borrow(self) as rusage_b:
                    await rsyscall.near.waitid(self.sysif, None, infop_b.near, options, rusage_b.near)

    async def sigprocmask(self, newset: t.Optional[t.Tuple[SigprocmaskHow, WrittenPointer[Sigset]]],
                          oldset: t.Optional[Pointer[Sigset]]=None) -> None:
        async with contextlib.AsyncExitStack() as stack:
            newset_b: t.Optional[t.Tuple[SigprocmaskHow, rsyscall.near.Pointer]]
            if newset:
                newset_b = newset[0], (await stack.enter_async_context(newset[1].borrow(self))).near
            else:
                newset_b = None
            oldset_b: t.Optional[rsyscall.near.Pointer]
            if oldset:
                oldset_b = (await stack.enter_async_context(oldset.borrow(self))).near
            else:
                oldset_b = None
            await rsyscall.near.rt_sigprocmask(self.sysif, newset_b, oldset_b, Sigset.sizeof())

    T_pointer_pipe = t.TypeVar('T_pointer_pipe', bound='Pointer[Pipe]')
    async def pipe(self, buf: T_pointer_pipe, flags: O) -> T_pointer_pipe:
        async with buf.borrow(self) as buf_b:
            await rsyscall.near.pipe2(self.sysif, buf_b.near, flags)
            return buf

    T_pointer_fdpair = t.TypeVar('T_pointer_fdpair', bound='Pointer[FDPair]')
    async def socketpair(self, domain: AF, type: SOCK, protocol: int, sv: T_pointer_fdpair) -> T_pointer_fdpair:
        async with sv.borrow(self) as sv_b:
            await rsyscall.near.socketpair(self.sysif, domain, type, protocol, sv_b.near)
            return sv

    async def execve(self, filename: WrittenPointer[Path],
                     argv: WrittenPointer[ArgList],
                     envp: WrittenPointer[ArgList],
                     flags: AT) -> None:
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(filename.borrow(self))
            for arg in [*argv.data, *envp.data]:
                await stack.enter_async_context(arg.borrow(self))
            await rsyscall.near.execveat(self.sysif, None, filename.near, argv.near, envp.near, flags)

    async def exit(self, status: int) -> None:
        await rsyscall.near.exit(self.sysif, status)

    async def _borrow_optional(self, stack: contextlib.AsyncExitStack, ptr: t.Optional[Pointer]
    ) -> t.Optional[rsyscall.near.Pointer]:
        if ptr is None:
            return None
        else:
            await stack.enter_async_context(ptr.borrow(self))
            return ptr.near

    async def clone(self, flags: CLONE,
                    # these two pointers must be adjacent; the end of the first is the start of the
                    # second. the first is the allocation for stack growth, the second is the data
                    # we've written on the stack that will be popped off for arguments.
                    child_stack: t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                    # these are both standard pointers to 4-byte integers
                    ptid: t.Optional[Pointer], ctid: t.Optional[Pointer],
                    # this points to anything, it depends on the thread implementation
                    newtls: t.Optional[Pointer]) -> t.Tuple[Process, Pointer[Stack]]:
        clone_parent = bool(flags & CLONE.PARENT)
        if clone_parent:
            print("clone parenting in HANDLE")
            if self.parent_task is None:
                raise Exception("using CLONE.PARENT, but we don't know our parent task")
            # TODO also check that the parent_task hasn't shut down... not sure how to do that
            owning_task = self.parent_task
        else:
            owning_task = self
        async with contextlib.AsyncExitStack() as stack:
            stack_alloc, stack_data = child_stack
            if (int(stack_data.near) % 16) != 0:
                raise Exception("child stack must have 16-byte alignment, so says Intel")
            stack_alloc_end = stack_alloc.near + stack_alloc.bytesize()
            if stack_alloc_end != stack_data.near:
                raise Exception("the end of the stack allocation pointer", stack_alloc_end,
                                "and the beginning of the stack data pointer", stack_data.near,
                                "must be the same")
            await stack.enter_async_context(stack_alloc.borrow(self))
            await stack.enter_async_context(stack_data.borrow(self))
            ptid_n = await self._borrow_optional(stack, ptid)
            ctid_n = await self._borrow_optional(stack, ctid)
            newtls_n = await self._borrow_optional(stack, newtls)
            process = await rsyscall.near.clone(self.sysif, flags, stack_data.near, ptid_n, ctid_n, newtls_n)
        # TODO the safety of this depends on no-one borrowing/freeing the stack in borrow __aexit__
        # should try to do this a bit more robustly...
        merged_stack = stack_alloc.merge(stack_data)
        return Process(owning_task, process), merged_stack

    async def mmap(self, length: int, prot: PROT, flags: MAP,
                   page_size: int=4096,
    ) -> MemoryMapping:
        # a mapping without a file descriptor, is an anonymous mapping
        flags |= MAP.ANONYMOUS
        ret = await rsyscall.near.mmap(self.sysif, length, prot, flags, page_size=page_size)
        return MemoryMapping(self, ret, File())

    async def set_robust_list(self, head: WrittenPointer[RobustListHead]) -> None:
        async with head.borrow(self):
            await rsyscall.near.set_robust_list(self.sysif, head.near, head.bytesize())

@dataclass
class FutexNode(Struct):
    # this is our bundle of struct robust_list with a futex.  since it's tricky to handle the
    # reference management of taking a reference to just one field in a structure (the futex, in
    # cases where we don't care about the robust list), we always deal in the entire FutexNode
    # structure whenever we talk about futexes. that's a bit of overhead but we barely use futexes,
    # so it's fine.
    next: t.Optional[Pointer[FutexNode]]
    futex: Int32

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct futex_node*', {
            # technically we're supposed to have a pointer to the first node in the robust list to
            # indicate the end.  but that's tricky to do. so instead let's just use a NULL pointer;
            # the kernel will EFAULT when it hits the end. make sure not to map 0, or we'll
            # break. https://imgflip.com/i/2zwysg
            'list': (ffi.cast('struct robust_list*', int(self.next.near)) if self.next else ffi.NULL,),
            'futex': self.futex,
        })
        return bytes(ffi.buffer(struct))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct futex_node')

@dataclass
class RobustListHead(Struct):
    first: WrittenPointer[FutexNode]

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct robust_list_head*', {
            'list': (ffi.cast('struct robust_list*', int(self.first.near)),),
            'futex_offset': ffi.offsetof('struct futex_node', 'futex'),
            'list_op_pending': ffi.NULL,
        })
        return bytes(ffi.buffer(struct))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct robust_list_head')

class Borrowable:
    async def borrow_with(self, stack: contextlib.AsyncExitStack, task: Task) -> None:
        raise NotImplementedError("borrow_with not implemented on", type(self))

T_borrowable = t.TypeVar('T_borrowable', bound=Borrowable)
@dataclass
class Stack(Serializable, t.Generic[T_borrowable]):
    function: Pointer
    data: T_borrowable
    serializer: Serializer[T_borrowable]

    async def borrow_with(self, stack: contextlib.AsyncExitStack, task: Task) -> None:
        await stack.enter_async_context(self.function.borrow(task))
        await self.data.borrow_with(stack, task)

    def to_bytes(self) -> bytes:
        return struct.Struct("Q").pack(int(self.function.near)) + self.serializer.to_bytes(self.data)

    T_stack = t.TypeVar('T_stack', bound='Stack')
    @classmethod
    def from_bytes(cls: t.Type[T_stack], data: bytes) -> T_stack:
        raise Exception("nay")

@dataclass
class Process:
    task: Task
    near: rsyscall.near.Process

    @property
    def far(self) -> rsyscall.far.Process:
        # TODO delete this property
        return rsyscall.far.Process(self.task.pidns, self.near)

    async def waitid(self, options: W, infop: Pointer[Siginfo],
                     *, rusage: t.Optional[Pointer[Siginfo]]=None) -> Pointer[Siginfo]:
        async with infop.borrow(self.task) as infop_b:
            if rusage is None:
                await rsyscall.near.waitid(self.task.sysif, self.near, infop_b.near, options, None)
            else:
                async with rusage.borrow(self.task) as rusage_b:
                    await rsyscall.near.waitid(self.task.sysif, self.near, infop_b.near, options, rusage_b.near)
        return infop

    async def kill(self, sig: Signals) -> None:
        await rsyscall.near.kill(self.task.sysif, self.near, sig)

@dataclass
class MemoryMapping:
    task: Task
    near: rsyscall.near.MemoryMapping
    file: File

    # TODO remove this
    def as_pointer(self) -> rsyscall.far.Pointer:
        return rsyscall.far.Pointer(self.task.address_space, self.near.as_pointer())

    async def munmap(self) -> None:
        await rsyscall.near.munmap(self.task.sysif, self.near)

T_pipe = t.TypeVar('T_pipe', bound='Pipe')
@dataclass
class Pipe(FixedSize):
    read: FileDescriptor
    write: FileDescriptor

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fdpair')

    @classmethod
    def get_serializer(cls: t.Type[T_pipe], task: Task) -> Serializer[T_pipe]:
        return PipeSerializer(cls, task)

@dataclass
class PipeSerializer(Serializer[T_pipe]):
    cls: t.Type[T_pipe]
    task: Task

    def to_bytes(self, pair: T_pipe) -> bytes:
        struct = ffi.new('struct fdpair*', (pair.read, pair.write))
        return bytes(ffi.buffer(struct))

    def from_bytes(self, data: bytes) -> T_pipe:
        struct = ffi.cast('struct fdpair const*', ffi.from_buffer(data))
        def make(n: int) -> FileDescriptor:
            return self.task.make_fd_handle(rsyscall.near.FileDescriptor(int(n)))
        return self.cls(make(struct.first), make(struct.second))

T_fdpair = t.TypeVar('T_fdpair', bound='FDPair')
@dataclass
class FDPair(FixedSize):
    first: FileDescriptor
    second: FileDescriptor

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fdpair')

    @classmethod
    def get_serializer(cls: t.Type[T_fdpair], task: Task) -> Serializer[T_fdpair]:
        return FDPairSerializer(cls, task)

@dataclass
class FDPairSerializer(Serializer[T_fdpair]):
    cls: t.Type[T_fdpair]
    task: Task

    def to_bytes(self, pair: T_fdpair) -> bytes:
        struct = ffi.new('struct fdpair*', (pair.first, pair.second))
        return bytes(ffi.buffer(struct))

    def from_bytes(self, data: bytes) -> T_fdpair:
        struct = ffi.cast('struct fdpair const*', ffi.from_buffer(data))
        def make(n: int) -> FileDescriptor:
            return self.task.make_fd_handle(rsyscall.near.FileDescriptor(int(n)))
        return self.cls(make(struct.first), make(struct.second))

class Arg(bytes, Serializable):
    def to_bytes(self) -> bytes:
        return self + b'\0'

    T = t.TypeVar('T', bound='Arg')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        try:
            nullidx = data.index(b'\0')
        except ValueError:
            return cls(data)
        else:
            return cls(data[0:nullidx])

T_arglist = t.TypeVar('T_arglist', bound='ArgList')
class ArgList(t.List[Pointer[Arg]], HasSerializer):
    @classmethod
    def get_serializer(cls, task: Task) -> Serializer[T_arglist]:
        return ArgListSerializer()

import struct
class ArgListSerializer(Serializer[T_arglist]):
    def to_bytes(self, arglist: T_arglist) -> bytes:
        ret = b""
        for ptr in arglist:
            ret += struct.Struct("Q").pack(int(ptr.near))
        ret += struct.Struct("Q").pack(0)
        return ret

    def from_bytes(self, data: bytes) -> T_arglist:
        raise Exception("can't get pointer handles from raw bytes")

################################################################################
# sendmsg/recvmsg
class IovecList(t.List[Pointer], Serializable):
    def split(self, n: int) -> t.Tuple[IovecList, IovecList]:
        valid: t.List[Pointer] = []
        invalid: t.List[Pointer] = []
        for ptr in self:
            size = ptr.bytesize()
            if size >= n:
                valid.append(ptr)
                n -= size
            elif n > 0:
                validp, invalidp = ptr.split(n)
                valid.append(validp)
                assert len(invalid) == 0
                invalid.append(invalidp)
                n = 0
            else:
                invalid.append(ptr)
        return IovecList(valid), IovecList(invalid)

    def to_bytes(self) -> bytes:
        ret = b""
        for ptr in self:
            ret += bytes(ffi.buffer(ffi.new('struct iovec const*', {
                "iov_base": ffi.cast('void*', int(ptr.near)),
                "iov_len": ptr.bytesize(),
            })))
        return ret

    T = t.TypeVar('T', bound='IovecList')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("can't get pointer handles from raw bytes")

T_cmsg = t.TypeVar('T_cmsg', bound='Cmsg')
class Cmsg(HasSerializer):
    @abc.abstractmethod
    def to_data(self) -> bytes: ...
    @abc.abstractmethod
    async def borrow_with(self, stack: contextlib.AsyncExitStack, task: Task) -> None: ...
    @classmethod
    @abc.abstractmethod
    def from_data(cls: t.Type[T], task: Task, data: bytes) -> T: ...
    @classmethod
    @abc.abstractmethod
    def level(cls: t.Type[T]) -> SOL: ...
    @classmethod
    @abc.abstractmethod
    def type(cls: t.Type[T]) -> int: ...

    @classmethod
    def get_serializer(cls: t.Type[T_cmsg], task: Task) -> Serializer[T_cmsg]:
        return CmsgSerializer(cls, task)

class CmsgSerializer(Serializer[T_cmsg]):
    def __init__(self, cls: t.Type[T_cmsg], task: Task) -> None:
        self.cls = cls
        self.task = task

    def to_bytes(self, val: T_cmsg) -> bytes:
        if not isinstance(val, self.cls):
            raise Exception("Serializer for", self.cls,
                            "had to_bytes called on different type", val)
        data = val.to_data()
        header = bytes(ffi.buffer(ffi.new('struct cmsghdr*', {
            "cmsg_len": ffi.sizeof('struct cmsghdr') + len(data),
            "cmsg_level": val.level(),
            "cmsg_type": val.type(),
        })))
        return header + data

    def from_bytes(self, data: bytes) -> T_cmsg:
        record = ffi.cast('struct cmsghdr*', ffi.from_buffer(data))
        if record.cmsg_level != self.cls.level():
            raise Exception("serializer for level", self.cls.level(),
                            "got message for level", record.cmsg_level)
        if record.cmsg_type != self.cls.type():
            raise Exception("serializer for type", self.cls.type(),
                            "got message for type", record.cmsg_type)
        return self.cls.from_data(self.task, data[ffi.sizeof('struct cmsghdr'):record.cmsg_len])

import array
class CmsgSCMRights(Cmsg, t.List[FileDescriptor]):
    def to_data(self) -> bytes:
        return array.array('i', (int(fd.near) for fd in self)).tobytes()
    async def borrow_with(self, stack: contextlib.AsyncExitStack, task: Task) -> None:
        for fd in self:
            await stack.enter_async_context(fd.borrow(task))

    T = t.TypeVar('T', bound='CmsgSCMRights')
    @classmethod
    def from_data(cls: t.Type[T], task: Task, data: bytes) -> T:
        fds = [rsyscall.near.FileDescriptor(fd) for fd, in struct.Struct('i').iter_unpack(data)]
        return cls([task.make_fd_handle(fd) for fd in fds])

    @classmethod
    def level(cls) -> SOL:
        return SOL.SOCKET
    @classmethod
    def type(cls) -> int:
        return SCM.RIGHTS

T_cmsglist = t.TypeVar('T_cmsglist', bound='CmsgList')
class CmsgList(t.List[Cmsg], HasSerializer):
    @classmethod
    def get_serializer(cls: t.Type[T_cmsglist], task: Task) -> Serializer[T_cmsglist]:
        return CmsgListSerializer(cls, task)

    async def borrow_with(self, stack: contextlib.AsyncExitStack, task: Task) -> None:
        for cmsg in self:
            await cmsg.borrow_with(stack, task)

class CmsgListSerializer(Serializer[T_cmsglist]):
    def __init__(self, cls: t.Type[T_cmsglist], task: Task) -> None:
        self.cls = cls
        self.task = task

    def to_bytes(self, val: T_cmsglist) -> bytes:
        ret = b""
        for cmsg in val:
            # TODO is this correct alignment/padding???
            # I don't think so...
            ret += cmsg.get_serializer(self.task).to_bytes(cmsg)
        return ret

    def from_bytes(self, data: bytes) -> T_cmsglist:
        entries = []
        while len(data) > 0:
            record = ffi.cast('struct cmsghdr*', ffi.from_buffer(data))
            record_data = data[:record.cmsg_len]
            level = SOL(record.cmsg_level)
            if level == SOL.SOCKET and record.cmsg_type == int(SCM.RIGHTS):
                entries.append(CmsgSCMRights.get_serializer(self.task).from_bytes(record_data))
            else:
                raise Exception("unknown cmsg level/type sorry", level, type)
            data = data[record.cmsg_len:]
        return self.cls(entries)

@dataclass
class SendMsghdr(Serializable):
    name: t.Optional[WrittenPointer[Address]]
    iov: WrittenPointer[IovecList]
    control: t.Optional[WrittenPointer[CmsgList]]

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct msghdr*', {
            "msg_name": ffi.cast('void*', int(self.name.near)) if self.name else ffi.NULL,
            "msg_namelen": self.name.bytesize() if self.name else 0,
            "msg_iov": ffi.cast('void*', int(self.iov.near)),
            "msg_iovlen": len(self.iov.value),
            "msg_control": ffi.cast('void*', int(self.control.near)) if self.control else ffi.NULL,
            "msg_controllen": self.control.bytesize() if self.control else 0,
            "msg_flags": 0,
        })))

    T = t.TypeVar('T', bound='SendMsghdr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("can't get pointer handles from raw bytes")

@dataclass
class RecvMsghdr(Serializable):
    name: t.Optional[Pointer[Address]]
    iov: WrittenPointer[IovecList]
    control: t.Optional[Pointer[CmsgList]]

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct msghdr*', {
            "msg_name": ffi.cast('void*', int(self.name.near)) if self.name else ffi.NULL,
            "msg_namelen": self.name.bytesize() if self.name else 0,
            "msg_iov": ffi.cast('void*', int(self.iov.near)),
            "msg_iovlen": len(self.iov.value),
            "msg_control": ffi.cast('void*', int(self.control.near)) if self.control else ffi.NULL,
            "msg_controllen": self.control.bytesize() if self.control else 0,
            "msg_flags": 0,
        })))

    T = t.TypeVar('T', bound='RecvMsghdr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("can't get pointer handles from raw bytes")

    def to_out(self, ptr: Pointer[RecvMsghdr]) -> Pointer[RecvMsghdrOut]:
        # what a mouthful
        serializer = RecvMsghdrOutSerializer(self.name, self.control)
        return ptr._reinterpret(serializer)

@dataclass
class RecvMsghdrOut:
    name: t.Optional[Pointer[Address]]
    control: t.Optional[Pointer[CmsgList]]
    flags: MsghdrFlags
    # the _rest fields are the invalid, unused parts of the buffers;
    # almost everyone can ignore these.
    name_rest: t.Optional[Pointer[Address]]
    control_rest: t.Optional[Pointer[CmsgList]]

@dataclass
class RecvMsghdrOutSerializer(Serializer[RecvMsghdrOut]):
    name: t.Optional[Pointer[Address]]
    control: t.Optional[Pointer[CmsgList]]

    def to_bytes(self, x: RecvMsghdrOut) -> bytes:
        raise Exception("not going to bother implementing this")

    def from_bytes(self, data: bytes) -> RecvMsghdrOut:
        struct = ffi.cast('struct msghdr*', ffi.from_buffer(data))
        if self.name is None:
            name: t.Optional[Pointer[Address]] = None
            name_rest: t.Optional[Pointer[Address]] = None
        else:
            name, name_rest = self.name.split(struct.msg_namelen)
        if self.control is None:
            control: t.Optional[Pointer[CmsgList]] = None
            control_rest: t.Optional[Pointer[CmsgList]] = None
        else:
            control, control_rest = self.control.split(struct.msg_controllen)
        flags = MsghdrFlags(struct.msg_flags)
        return RecvMsghdrOut(name, control, flags, name_rest, control_rest)

class NativeFunction:
    pass

class NativeFunctionSerializer(Serializer[NativeFunction]):
    pass
