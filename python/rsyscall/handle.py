from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass, field
import copy
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
logger = logging.getLogger(__name__)

from rsyscall.sys.socket import (
    AF, SOCK, SOL, SCM, Address, Sockbuf, SendmsgFlags, RecvmsgFlags, MsghdrFlags, T_addr,
    SendMsghdr, RecvMsghdr, RecvMsghdrOut,
    CmsgList, CmsgSCMRights,
    FDPair,
)
from rsyscall.sched import UnshareFlag, CLONE, Stack, Borrowable
from rsyscall.struct import Serializer, HasSerializer, FixedSerializer, FixedSize, Serializable, Int32, Struct
from rsyscall.signal import Sigaction, Sigset, Signals, Siginfo, SignalMaskTask
from rsyscall.fcntl import AT, F, O
from rsyscall.path import Path, EmptyPath
from rsyscall.unistd import SEEK, Arg, ArgList, Pipe, OK
from rsyscall.sys.epoll import EpollFlag, EPOLL_CTL, EpollEvent, EpollEventList
from rsyscall.linux.dirent import DirentList
from rsyscall.linux.futex import RobustListHead, FutexNode
from rsyscall.sys.inotify import InotifyFlag, IN
from rsyscall.sys.memfd import MFD
from rsyscall.sys.wait import W, ChildEvent
from rsyscall.sys.mman import MAP, PROT
from rsyscall.sys.prctl import PrctlOp
from rsyscall.sys.mount import MS
from rsyscall.sys.uio import RWF, IovecList, split_iovec

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

class MemoryGateway:
    @abc.abstractmethod
    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]: ...

    async def read(self, src: Pointer) -> bytes:
        [data] = await self.batch_read([src])
        return data

    @abc.abstractmethod
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None: ...

    async def write(self, dest: Pointer, data: bytes) -> None:
        await self.batch_write([(dest, data)])

class MemoryTransport(MemoryGateway):
    @abc.abstractmethod
    def inherit(self, task: Task) -> MemoryTransport: ...

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
    transport: MemoryGateway
    serializer: Serializer[T]
    allocation: AllocationInterface
    valid: bool = True

    @property
    def near(self) -> rsyscall.near.Pointer:
        # TODO hmm should maybe validate that this fits in the bounds of the mapping I guess
        self.validate()
        return self.mapping.near.as_pointer() + self.allocation.offset()

    def bytesize(self) -> int:
        return self.allocation.size()

    @contextlib.contextmanager
    def borrow(self, task: rsyscall.far.Task) -> t.Iterator[Pointer]:
        # TODO actual tracking of pointer references is not yet implemented
        self.validate()
        if task.address_space != self.mapping.task.address_space:
            raise Exception("pointer is in different address space")
        yield self

    def _with_alloc(self, allocation: AllocationInterface) -> Pointer:
        return Pointer(self.mapping, self.transport, self.serializer, allocation)

    def _with_mapping(self: T_pointer, mapping: MemoryMapping) -> T_pointer:
        if type(self) is not Pointer:
            raise Exception("subclasses of Pointer must override _with_mapping")
        if mapping.file is not self.mapping.file:
            raise Exception("can only move pointer between two mappings of the same file")
        # we don't have a clean model for referring to the same object through multiple mappings.
        # this is a major TODO.
        # at least two ways to achieve it:
        # - have Pointers become multi-mapping super-pointers, which can be valid in multiple address spaces
        # - break our linearity constraint on pointers, allowing multiple pointers for the same allocation;
        #   this is difficult because split() is only easy due to linearity.
        # right here, we just linearly move the pointer to a new mapping
        self.validate()
        self.valid = False
        return type(self)(mapping, self.transport, self.serializer, self.allocation)

    def split(self, size: int) -> t.Tuple[Pointer, Pointer]:
        self.validate()
        # TODO uhhhh if split throws an exception... don't we need to free... or something...
        self.valid = False
        # TODO we should only allow split if we are the only reference to this allocation
        alloc1, alloc2 = self.allocation.split(size)
        first = self._with_alloc(alloc1)
        # TODO should degrade this pointer to raw bytes or something, or maybe no type at all
        second = self._with_alloc(alloc2)
        return first, second

    def merge(self, ptr: Pointer) -> Pointer:
        self.validate()
        ptr.validate()
        # TODO should assert that these two pointers both serialize the same thing
        # although they could be different types of serializers...
        self.valid = False
        # TODO we should only allow merge if we are the only reference to this allocation
        alloc = self.allocation.merge(ptr.allocation)
        return self._with_alloc(alloc)

    def __add__(self, right: Pointer[T]) -> Pointer[T]:
        return self.merge(right)

    def __radd__(self, left: t.Optional[Pointer[T]]) -> Pointer[T]:
        if left is None:
            return self
        else:
            return left + self

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
        await self.transport.write(self, data_bytes)
        return self._wrote(data)

    def split_from_end(self, size: int, alignment: int) -> t.Tuple[Pointer, Pointer]:
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
        data = await self.transport.read(self)
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
                 transport: MemoryGateway,
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

    def _with_mapping(self, mapping: MemoryMapping) -> WrittenPointer:
        if type(self) is not WrittenPointer:
            raise Exception("subclasses of WrittenPointer must override _with_mapping")
        if mapping.file is not self.mapping.file:
            raise Exception("can only move pointer between two mappings of the same file")
        # see notes in Pointer
        self.validate()
        self.valid = False
        return type(self)(mapping, self.transport, self.data, self.serializer, self.allocation)

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

    @contextlib.contextmanager
    def borrow(self, task: Task) -> t.Iterator[FileDescriptor]:
        if self.task == task:
            yield self
        else:
            borrowed = self.for_task(task)
            try:
                yield borrowed
            finally:
                # we can't call invalidate since we can't actually close this fd since that would
                # require more syscalls. we should really make it so that if the user tries to
                # invalidate the fd they passed into a syscall, they get an exception when they call
                # invalidate. but in lieu of that, we'll throw here. this will cause us to drop
                # events from syscalls, which would break a system that wants to handle exceptions
                # and resume, so we should fix this later. TODO
                # hmm actually I think it might be fine to borrow an fd and free its original?
                # that will happen if we borrow an expression... which should be fine...
                # maybe borrow is a bad design.
                # maybe borrow should just mean, you can't invalidate this fd right now.
                # though we do want to also check that it's the right address space...
                if borrowed.valid:
                    borrowed.valid = False
                    if len(borrowed._remove_from_tracking()) == 0:
                        raise Exception("borrowed fd must have been freed from under us, %s", borrowed)

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

    async def read(self, buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        self.validate()
        with buf.borrow(self.task) as buf_b:
            ret = await rsyscall.near.read(self.task.sysif, self.near, buf_b.near, buf_b.bytesize())
            return buf.split(ret)

    async def readv(self, iov: WrittenPointer[IovecList], flags: RWF=RWF.NONE
    ) -> t.Tuple[WrittenPointer[IovecList], t.Optional[t.Tuple[Pointer, Pointer]], WrittenPointer[IovecList]]:
        # TODO should check that the WrittenPointer's value and size correspond...
        # maybe we should check that at construction time?
        # otherwise one could make a WrittenPointer that is short, but has a long iovec, and we'd read off the end.
        with contextlib.ExitStack() as stack:
            stack.enter_context(iov.borrow(self.task))
            ret = await rsyscall.near.preadv2(self.task.sysif, self.near, iov.near, len(iov.value), -1, flags)
            return split_iovec(iov, ret)

    async def writev(self, iov: WrittenPointer[IovecList], flags: RWF=RWF.NONE
    ) -> t.Tuple[WrittenPointer[IovecList], t.Optional[t.Tuple[Pointer, Pointer]], WrittenPointer[IovecList]]:
        with contextlib.ExitStack() as stack:
            stack.enter_context(iov.borrow(self.task))
            ret = await rsyscall.near.pwritev2(self.task.sysif, self.near, iov.near, len(iov.value), -1, flags)
            return split_iovec(iov, ret)

    async def write(self, buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        self.validate()
        with buf.borrow(self.task) as buf_b:
            ret = await rsyscall.near.write(self.task.sysif, self.near, buf_b.near, buf_b.bytesize())
            return buf.split(ret)

    async def sendmsg(self, msg: WrittenPointer[SendMsghdr], flags: SendmsgFlags
    ) -> t.Tuple[IovecList, IovecList]:
        with contextlib.ExitStack() as stack:
            stack.enter_context(msg.borrow(self.task))
            if msg.value.name:
                stack.enter_context(msg.value.name.borrow(self.task))
            if msg.value.control:
                stack.enter_context(msg.value.control.borrow(self.task))
                msg.value.control.value.borrow_with(stack, self.task)
            stack.enter_context(msg.value.iov.borrow(self.task))
            for iovec_elem in msg.value.iov.value:
                stack.enter_context(iovec_elem.borrow(self.task))
            ret = await rsyscall.near.sendmsg(self.task.sysif, self.near, msg.near, flags)
        return msg.value.iov.value.split(ret)

    async def recvmsg(self, msg: WrittenPointer[RecvMsghdr], flags: RecvmsgFlags
    ) -> t.Tuple[IovecList, IovecList, Pointer[RecvMsghdrOut]]:
        with contextlib.ExitStack() as stack:
            stack.enter_context(msg.borrow(self.task))
            if msg.value.name:
                stack.enter_context(msg.value.name.borrow(self.task))
            if msg.value.control:
                stack.enter_context(msg.value.control.borrow(self.task))
            stack.enter_context(msg.value.iov.borrow(self.task))
            for iovec_elem in msg.value.iov.value:
                stack.enter_context(iovec_elem.borrow(self.task))
            ret = await rsyscall.near.recvmsg(self.task.sysif, self.near, msg.near, flags)
        valid, invalid = msg.value.iov.value.split(ret)
        return valid, invalid, msg.value.to_out(msg)

    async def recv(self, buf: Pointer, flags: int) -> t.Tuple[Pointer, Pointer]:
        self.validate()
        with buf.borrow(self.task) as buf_b:
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
        with newfd.borrow(self.task):
            if self.near == newfd.near:
                # dup3 fails if newfd == oldfd. I guess I'll just work around that.
                return newfd
            await rsyscall.near.dup3(self.task.sysif, self.near, newfd.near, flags)
            # newfd is left as a valid pointer to the new file descriptor
            return newfd

    async def copy_from(self, source: FileDescriptor, flags=0) -> None:
        await source.dup3(self, flags)

    async def replace_with(self, source: FileDescriptor, flags=0) -> None:
        await source.dup3(self, flags)
        await source.invalidate()

    async def fcntl(self, cmd: F, arg: t.Optional[int]=None) -> int:
        self.validate()
        return (await rsyscall.near.fcntl(self.task.sysif, self.near, cmd, arg))

    async def ioctl(self, request: int, arg: Pointer) -> int:
        self.validate()
        arg.validate()
        return (await rsyscall.near.ioctl(self.task.sysif, self.near, request, arg.near))

    async def setns(self, nstype: int) -> None:
        self.validate()
        await rsyscall.near.setns(self.task.sysif, self.near, nstype)

    async def epoll_wait(self, events: Pointer[EpollEventList], timeout: int) -> t.Tuple[Pointer[EpollEventList], Pointer]:
        self.validate()
        with events.borrow(self.task) as events_b:
            num = await rsyscall.near.epoll_wait(
                self.task.sysif, self.near, events_b.near, events_b.bytesize()//EpollEvent.sizeof(), timeout)
            valid_size = num * EpollEvent.sizeof()
            return events.split(valid_size)

    async def epoll_ctl(self, op: EPOLL_CTL, fd: FileDescriptor, event: t.Optional[Pointer[EpollEvent]]=None) -> None:
        self.validate()
        with fd.borrow(self.task) as fd:
            if event is not None:
                if event.bytesize() < EpollEvent.sizeof():
                    raise Exception("pointer is too small", event.bytesize(), "to be an EpollEvent", EpollEvent.sizeof())
                with event.borrow(self.task) as eventp:
                    return (await rsyscall.near.epoll_ctl(self.task.sysif, self.near, op, fd.near, eventp.near))
            else:
                return (await rsyscall.near.epoll_ctl(self.task.sysif, self.near, op, fd.near))

    async def inotify_add_watch(self, pathname: WrittenPointer[Path], mask: IN) -> rsyscall.near.WatchDescriptor:
        self.validate()
        with pathname.borrow(self.task) as pathname_b:
            return (await rsyscall.near.inotify_add_watch(self.task.sysif, self.near, pathname_b.near, mask))

    async def inotify_rm_watch(self, wd: rsyscall.near.WatchDescriptor) -> None:
        self.validate()
        await rsyscall.near.inotify_rm_watch(self.task.sysif, self.near, wd)

    async def bind(self, addr: WrittenPointer[Address]) -> None:
        self.validate()
        with addr.borrow(self.task):
            await rsyscall.near.bind(self.task.sysif, self.near, addr.near, addr.bytesize())

    async def connect(self, addr: WrittenPointer[Address]) -> None:
        self.validate()
        with addr.borrow(self.task):
            await rsyscall.near.connect(self.task.sysif, self.near, addr.near, addr.bytesize())

    async def listen(self, backlog: int) -> None:
        self.validate()
        await rsyscall.near.listen(self.task.sysif, self.near, backlog)

    async def getsockopt(self, level: int, optname: int, optval: WrittenPointer[Sockbuf[T]]) -> Pointer[Sockbuf[T]]:
        self.validate()
        with optval.borrow(self.task):
            with optval.value.buf.borrow(self.task):
                await rsyscall.near.getsockopt(self.task.sysif, self.near,
                                               level, optname, optval.value.buf.near, optval.near)
        return optval

    async def setsockopt(self, level: int, optname: int, optval: Pointer) -> None:
        self.validate()
        with optval.borrow(self.task) as optval_b:
            await rsyscall.near.setsockopt(self.task.sysif, self.near, level, optname, optval_b.near, optval_b.bytesize())

    async def getsockname(self, addr: WrittenPointer[Sockbuf[T_addr]]) -> Pointer[Sockbuf[T_addr]]:
        self.validate()
        with addr.borrow(self.task):
            with addr.value.buf.borrow(self.task):
                await rsyscall.near.getsockname(self.task.sysif, self.near, addr.value.buf.near, addr.near)
        return addr

    async def getpeername(self, addr: WrittenPointer[Sockbuf[T_addr]]) -> Pointer[Sockbuf[T_addr]]:
        self.validate()
        with addr.borrow(self.task):
            with addr.value.buf.borrow(self.task):
                await rsyscall.near.getpeername(self.task.sysif, self.near, addr.value.buf.near, addr.near)
        return addr

    @t.overload
    async def accept(self, flags: SOCK) -> FileDescriptor: ...
    @t.overload
    async def accept(self, flags: SOCK, addr: WrittenPointer[Sockbuf[T_addr]]
    ) -> t.Tuple[FileDescriptor, WrittenPointer[Sockbuf[T_addr]]]: ...

    async def accept(self, flags: SOCK, addr: t.Optional[WrittenPointer[Sockbuf[T_addr]]]=None
    ) -> t.Union[FileDescriptor, t.Tuple[FileDescriptor, WrittenPointer[Sockbuf[T_addr]]]]:
        self.validate()
        if addr is None:
            fd = await rsyscall.near.accept4(self.task.sysif, self.near, None, None, flags)
            return self.task.make_fd_handle(fd)
        else:
            with addr.borrow(self.task):
                with addr.value.buf.borrow(self.task):
                    fd = await rsyscall.near.accept4(self.task.sysif, self.near, addr.value.buf.near, addr.near, flags)
                    return self.task.make_fd_handle(fd), addr

    async def readlinkat(self, path: t.Union[WrittenPointer[Path], WrittenPointer[EmptyPath]],
                         buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        self.validate()
        with path.borrow(self.task):
            with buf.borrow(self.task):
                ret = await rsyscall.near.readlinkat(self.task.sysif, self.near, path.near, buf.near, buf.bytesize())
                return buf.split(ret)

    async def faccessat(self, ptr: WrittenPointer[Path], mode: OK, flags: AT=AT.NONE) -> None:
        self.validate()
        with ptr.borrow(self.task):
            await rsyscall.near.faccessat(self.task.sysif, self.near, ptr.near, mode, flags)

    async def getdents(self, dirp: Pointer[DirentList]) -> t.Tuple[Pointer[DirentList], Pointer]:
        self.validate()
        with dirp.borrow(self.task) as dirp_b:
            ret = await rsyscall.near.getdents64(self.task.sysif, self.near, dirp_b.near, dirp_b.bytesize())
            return dirp.split(ret)

    async def signalfd(self, mask: Pointer[Sigset], flags: int) -> None:
        self.validate()
        with mask.borrow(self.task) as mask:
            await rsyscall.near.signalfd4(self.task.sysif, self.near, mask.near, mask.bytesize(), flags)

    async def openat(self, ptr: WrittenPointer[Path], flags: O, mode=0o644) -> FileDescriptor:
        self.validate()
        with ptr.borrow(self.task):
            fd = await rsyscall.near.openat(self.task.sysif, self.near, ptr.near, flags, mode)
            return self.task.make_fd_handle(fd)

fd_table_to_near_to_handles: t.Dict[rsyscall.far.FDTable, t.Dict[rsyscall.near.FileDescriptor, t.List[FileDescriptor]]] = {}
fd_table_to_task: t.Dict[rsyscall.far.FDTable, t.List[Task]] = {}

async def run_fd_table_gc(fd_table: rsyscall.far.FDTable) -> None:
    near_to_handles = fd_table_to_near_to_handles[fd_table]
    fds_to_close = [fd for fd, handles in near_to_handles.items() if not handles]
    if not fds_to_close:
        return
    tasks = fd_table_to_task[fd_table]
    for task in list(tasks):
        if task.fd_table is not fd_table:
            tasks.remove(task)
        elif task.manipulating_fd_table:
            # skip tasks currently changing fd table
            pass
        else:
            break
    else:
        # uh, there's no valid task available? I guess just do nothing?
        return
    async def close_fd(fd: rsyscall.near.FileDescriptor) -> None:
        del near_to_handles[fd]
        # TODO I guess we should take a lock on the fd table
        try:
            # TODO we should mark this task as dead and fall back to later tasks in the list if
            # we fail due to a SyscallInterface-level error; that might happen if, say, this is
            # some decrepit task where we closed the syscallinterface but didn't exit the task.
            await rsyscall.near.close(task.sysif, fd)
        except:
            if fd in fd_table_to_near_to_handles:
                raise Exception("somehow someone else closed fd", fd, "and then it was reopened???")
            # put the fd back, I guess.
            near_to_handles[fd] = []
    async with trio.open_nursery() as nursery:
        for fd in fds_to_close:
            nursery.start_soon(close_fd, fd)

class RootExecError(Exception):
    pass

class Task(SignalMaskTask, rsyscall.far.Task):
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
        self.manipulating_fd_table = False
        self._setup_fd_table()
        self.__post_init__()

    def __post_init__(self) -> None:
        super().__post_init__()

    @property
    def base(self) -> Task:
        # backwards-compat hack, TODO delete
        return self

    def make_path_from_bytes(self, path: t.Union[str, bytes]) -> Path:
        return Path(os.fsdecode(path))

    def make_path_handle(self, path: Path) -> Path:
        return path

    def make_fd_handle(self, fd: t.Union[rsyscall.near.FileDescriptor,
                                         rsyscall.far.FileDescriptor,
                                         FileDescriptor]) -> FileDescriptor:
        if self.manipulating_fd_table:
            raise Exception("can't make a new FD handle while manipulating_fd_table==True")
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

    def _setup_fd_table_handles(self) -> None:
        near_to_handles = fd_table_to_near_to_handles.setdefault(self.fd_table, {})
        for handle in self.fd_handles:
            near_to_handles.setdefault(handle.near, []).append(handle)

    def _setup_fd_table(self) -> None:
        fd_table_to_task.setdefault(self.fd_table, []).append(self)
        self._setup_fd_table_handles()

    async def unshare_files(self) -> None:
        if self.manipulating_fd_table:
            raise Exception("can't unshare_files while manipulating_fd_table==True")
        # do a GC now to improve efficiency when GCing both tables after the unshare
        gc.collect()
        await run_fd_table_gc(self.fd_table)
        old_fd_table = self.fd_table
        self.fd_table = rsyscall.far.FDTable(self.sysif.identifier_process.id)
        self._setup_fd_table()
        self.manipulating_fd_table = True
        # perform the actual unshare
        await rsyscall.near.unshare(self.sysif, UnshareFlag.FILES)
        self.manipulating_fd_table = False
        # We can only remove our handles from the handle lists after the unshare is done
        # and the fds are safely copied, because otherwise someone else running GC on the
        # old fd table would close our fds when they notice there are no more handles.
        old_near_to_handles = fd_table_to_near_to_handles[old_fd_table]
        for handle in self.fd_handles:
            old_near_to_handles[handle.near].remove(handle)
        await run_fd_table_gc(old_fd_table)
        await run_fd_table_gc(self.fd_table)

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

    async def unshare_mount(self) -> None:
        await rsyscall.near.unshare(self.sysif, UnshareFlag.NEWNS)

    async def setns_user(self, fd: FileDescriptor) -> None:
        with fd.borrow(self) as fd:
            # can't setns to a user namespace while sharing CLONE_FS
            await self.unshare_fs()
            await fd.setns(UnshareFlag.NEWUSER)

    async def setns_net(self, fd: FileDescriptor) -> None:
        with fd.borrow(self) as fd:
            await fd.setns(UnshareFlag.NEWNET)

    async def socket(self, family: AF, type: SOCK, protocol: int=0, cloexec=True) -> FileDescriptor:
        if cloexec:
            type |= lib.SOCK_CLOEXEC
        sockfd = await rsyscall.near.socket(self.sysif, family, type, protocol)
        return self.make_fd_handle(sockfd)

    async def capset(self, hdrp: Pointer, datap: Pointer) -> None:
        with hdrp.borrow(self) as hdrp:
            with datap.borrow(self) as datap:
                await rsyscall.near.capset(self.sysif, hdrp.near, datap.near)

    async def capget(self, hdrp: Pointer, datap: Pointer) -> None:
        with hdrp.borrow(self) as hdrp:
            with datap.borrow(self) as datap:
                await rsyscall.near.capget(self.sysif, hdrp.near, datap.near)

    async def sigaction(self, signum: Signals,
                        act: t.Optional[Pointer[Sigaction]],
                        oldact: t.Optional[Pointer[Sigaction]]) -> None:
        with contextlib.ExitStack() as stack:
            if act:
                act = stack.enter_context(act.borrow(self))
            if oldact:
                oldact = stack.enter_context(oldact.borrow(self))
            # rt_sigaction takes the size of the sigset, not the size of the sigaction;
            # and sigset is a fixed size.
            await rsyscall.near.rt_sigaction(self.sysif, signum,
                                             act.near if act else None,
                                             oldact.near if oldact else None,
                                             Sigset.sizeof())

    async def open(self, ptr: WrittenPointer[Path], flags: O, mode=0o644) -> FileDescriptor:
        with ptr.borrow(self) as ptr_b:
            fd = await rsyscall.near.openat(self.sysif, None, ptr_b.near, flags, mode)
            return self.make_fd_handle(fd)

    async def mkdir(self, ptr: WrittenPointer[Path], mode=0o644) -> None:
        with ptr.borrow(self) as ptr_b:
            await rsyscall.near.mkdirat(self.sysif, None, ptr_b.near, mode)

    async def access(self, ptr: WrittenPointer[Path], mode: int, flags: int=0) -> None:
        with ptr.borrow(self) as ptr_b:
            await rsyscall.near.faccessat(self.sysif, None, ptr_b.near, mode, flags)

    async def unlink(self, ptr: WrittenPointer[Path]) -> None:
        with ptr.borrow(self) as ptr_b:
            await rsyscall.near.unlinkat(self.sysif, None, ptr_b.near, 0)

    async def rmdir(self, ptr: WrittenPointer[Path]) -> None:
        with ptr.borrow(self) as ptr_b:
            await rsyscall.near.unlinkat(self.sysif, None, ptr_b.near, AT.REMOVEDIR)

    async def link(self, oldpath: WrittenPointer[Path], newpath: WrittenPointer[Path]) -> None:
        with oldpath.borrow(self) as oldpath_b:
            with newpath.borrow(self) as newpath_b:
                await rsyscall.near.linkat(self.sysif, None, oldpath_b.near, None, newpath_b.near, 0)

    async def rename(self, oldpath: WrittenPointer[Path], newpath: WrittenPointer[Path]) -> None:
        with oldpath.borrow(self) as oldpath_b:
            with newpath.borrow(self) as newpath_b:
                await rsyscall.near.renameat2(self.sysif, None, oldpath_b.near, None, newpath_b.near, 0)

    async def symlink(self, target: WrittenPointer, linkpath: WrittenPointer[Path]) -> None:
        with target.borrow(self) as target_b:
            with linkpath.borrow(self) as linkpath_b:
                await rsyscall.near.symlinkat(self.sysif, target_b.near, None, linkpath_b.near)

    async def chdir(self, path: WrittenPointer[Path]) -> None:
        with path.borrow(self) as path_b:
            await rsyscall.near.chdir(self.sysif, path_b.near)

    async def fchdir(self, fd: FileDescriptor) -> None:
        with fd.borrow(self) as fd:
            await rsyscall.near.fchdir(self.sysif, fd.near)

    async def readlink(self, path: WrittenPointer[Path], buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        with path.borrow(self) as path_b:
            with buf.borrow(self) as buf_b:
                ret = await rsyscall.near.readlinkat(self.sysif, None, path_b.near, buf_b.near, buf_b.bytesize())
                return buf.split(ret)

    async def signalfd(self, mask: Pointer[Sigset], flags: int) -> FileDescriptor:
        with mask.borrow(self) as mask:
            fd = await rsyscall.near.signalfd4(self.sysif, None, mask.near, mask.bytesize(), flags)
            return self.make_fd_handle(fd)

    async def epoll_create(self, flags: EpollFlag) -> FileDescriptor:
        fd = await rsyscall.near.epoll_create(self.sysif, flags)
        return self.make_fd_handle(fd)

    async def inotify_init(self, flags: InotifyFlag) -> FileDescriptor:
        fd = await rsyscall.near.inotify_init(self.sysif, flags)
        return self.make_fd_handle(fd)

    async def memfd_create(self, name: WrittenPointer[Path], flags: MFD) -> FileDescriptor:
        with name.borrow(self) as name_b:
            fd = await rsyscall.near.memfd_create(self.sysif, name_b.near, flags)
            return self.make_fd_handle(fd)

    async def waitid(self, options: W, infop: Pointer[Siginfo],
                     *, rusage: t.Optional[Pointer[Siginfo]]=None) -> None:
        with infop.borrow(self) as infop_b:
            if rusage is None:
                await rsyscall.near.waitid(self.sysif, None, infop_b.near, options, None)
            else:
                with rusage.borrow(self) as rusage_b:
                    await rsyscall.near.waitid(self.sysif, None, infop_b.near, options, rusage_b.near)

    async def pipe(self, buf: Pointer[Pipe], flags: O=O.CLOEXEC) -> Pointer[Pipe]:
        with buf.borrow(self):
            await rsyscall.near.pipe2(self.sysif, buf.near, flags)
            return buf

    async def socketpair(self, domain: AF, type: SOCK, protocol: int, sv: Pointer[FDPair]) -> Pointer[FDPair]:
        with sv.borrow(self) as sv_b:
            await rsyscall.near.socketpair(self.sysif, domain, type, protocol, sv_b.near)
            return sv

    async def execve(self, filename: WrittenPointer[Path],
                     argv: WrittenPointer[ArgList],
                     envp: WrittenPointer[ArgList],
                     flags: AT) -> ChildProcess:
        with contextlib.ExitStack() as stack:
            stack.enter_context(filename.borrow(self))
            for arg in [*argv.data, *envp.data]:
                stack.enter_context(arg.borrow(self))
            self.manipulating_fd_table = True
            await rsyscall.near.execveat(self.sysif, None, filename.near, argv.near, envp.near, flags)
            self.manipulating_fd_table = False
            self.fd_table = rsyscall.far.FDTable(self.sysif.identifier_process.id)
            self._setup_fd_table_handles()
            if isinstance(self.process, ChildProcess):
                return self.process.did_exec()
            else:
                raise RootExecError("A task that isn't a ChildProcess called exec, "
                                    "and now we can't monitor it.")

    async def exit(self, status: int) -> None:
        self.manipulating_fd_table = True
        await rsyscall.near.exit(self.sysif, status)
        self.manipulating_fd_table = False
        self.fd_table = rsyscall.far.FDTable(self.sysif.identifier_process.id)
        await self.close_task()

    async def close_task(self):
        # close the syscall interface and kill the process; we don't have to do this since it'll be
        # GC'd, but maybe we want to be tidy in advance.
        await self.sysif.close_interface()

    async def clone(self, flags: CLONE,
                    # these two pointers must be adjacent; the end of the first is the start of the
                    # second. the first is the allocation for stack growth, the second is the data
                    # we've written on the stack that will be popped off for arguments.
                    child_stack: t.Tuple[Pointer[Stack], WrittenPointer[Stack]],
                    ptid: t.Optional[Pointer],
                    ctid: t.Optional[Pointer[FutexNode]],
                    # this points to anything, it depends on the thread implementation
                    newtls: t.Optional[Pointer]) -> ThreadProcess:
        clone_parent = bool(flags & CLONE.PARENT)
        if clone_parent:
            if self.parent_task is None:
                raise Exception("using CLONE.PARENT, but we don't know our parent task")
            # TODO also check that the parent_task hasn't shut down... not sure how to do that
            owning_task = self.parent_task
        else:
            owning_task = self
        with contextlib.ExitStack() as stack:
            stack_alloc, stack_data = child_stack
            if (int(stack_data.near) % 16) != 0:
                raise Exception("child stack must have 16-byte alignment, so says Intel")
            stack_alloc_end = stack_alloc.near + stack_alloc.bytesize()
            if stack_alloc_end != stack_data.near:
                raise Exception("the end of the stack allocation pointer", stack_alloc_end,
                                "and the beginning of the stack data pointer", stack_data.near,
                                "must be the same")
            stack.enter_context(stack_alloc.borrow(self))
            stack.enter_context(stack_data.borrow(self))
            ptid_n = await self._borrow_optional(stack, ptid)
            ctid_n = await self._borrow_optional(stack, ctid)
            newtls_n = await self._borrow_optional(stack, newtls)
            process = await rsyscall.near.clone(self.sysif, flags, stack_data.near, ptid_n,
                                                ctid_n + ffi.offsetof('struct futex_node', 'futex') if ctid_n else None,
                                                newtls_n)
        # TODO the safety of this depends on no-one borrowing/freeing the stack in borrow __aexit__
        # should try to do this a bit more robustly...
        merged_stack = stack_alloc.merge(stack_data)
        return ThreadProcess(owning_task, process, merged_stack, stack_data.value, ctid, newtls)

    async def mmap(self, length: int, prot: PROT, flags: MAP,
                   page_size: int=4096,
    ) -> MemoryMapping:
        # a mapping without a file descriptor, is an anonymous mapping
        flags |= MAP.ANONYMOUS
        ret = await rsyscall.near.mmap(self.sysif, length, prot, flags, page_size=page_size)
        return MemoryMapping(self, ret, File())

    async def set_robust_list(self, head: WrittenPointer[RobustListHead]) -> None:
        with head.borrow(self):
            await rsyscall.near.set_robust_list(self.sysif, head.near, head.bytesize())

    async def setsid(self) -> int:
        return (await rsyscall.near.setsid(self.sysif))

    async def prctl(self, option: PrctlOp, arg2: int,
                    arg3: int=None, arg4: int=None, arg5: int=None) -> int:
        return (await rsyscall.near.prctl(self.sysif, option, arg2, arg3, arg4, arg5))

    async def mount(self,
                    source: WrittenPointer[Arg], target: WrittenPointer[Arg],
                    filesystemtype: WrittenPointer[Arg], mountflags: MS,
                    data: WrittenPointer[Arg]) -> None:
        with source.borrow(self):
            with target.borrow(self):
                with filesystemtype.borrow(self):
                    with data.borrow(self):
                        return (await rsyscall.near.mount(
                            self.sysif,
                            source.near, target.near, filesystemtype.near,
                            mountflags, data.near))

    async def getuid(self) -> int:
        return (await rsyscall.near.getuid(self.sysif))

    async def getgid(self) -> int:
        return (await rsyscall.near.getgid(self.sysif))


################################################################################
# Processes

@dataclass
class Process:
    task: Task
    near: rsyscall.near.Process

    @property
    def far(self) -> rsyscall.far.Process:
        # TODO delete this property
        return rsyscall.far.Process(self.task.pidns, self.near)

    async def kill(self, sig: Signals) -> None:
        await rsyscall.near.kill(self.task.sysif, self.near, sig)

class ChildProcess(Process):
    def __init__(self, task: Task, near: rsyscall.near.Process, alive=True) -> None:
        self.task = task
        self.near = near
        self.death_event: t.Optional[ChildEvent] = None
        self.unread_siginfo: t.Optional[Pointer[Siginfo]] = None
        self.in_use = False

    def mark_dead(self, event: ChildEvent) -> None:
        self.death_event = event

    def did_exec(self) -> ChildProcess:
        return self

    @contextlib.contextmanager
    def borrow(self) -> t.Iterator[None]:
        if self.death_event:
            raise Exception("child process", self.near, "is no longer alive, so we can't wait on it or kill it")
        if self.unread_siginfo:
            raise Exception("for child process", self.near, "waitid or kill was call "
                            "before processing the siginfo buffer from an earlier waitid")
        if self.in_use:
            # TODO technically we could have multiple kills happening simultaneously.
            # but indeed, we can't have a kill happen while a wait is happening, nor multiple waits at a time.
            # that would be racy - we might kill the wrong process or wait on the wrong process
            raise Exception("child process", self.near, "is currently being waited on or killed,"
                            " can't use it a second time")
        self.in_use = True
        try:
            yield
        finally:
            self.in_use = False

    async def kill(self, sig: Signals) -> None:
        with self.borrow():
            await super().kill(sig)

    async def waitid(self, options: W, infop: Pointer[Siginfo],
                     *, rusage: t.Optional[Pointer[Siginfo]]=None) -> None:
        # TODO it's important that the Siginfo buffer passed to waitid is stored carefully if waitid returns;
        # otherwise we could drop events if we're cancelled while trying to read the buffer.
        # maybe... we should store it ourselves? hm.
        # Likewise, it's important that this class be informed when the process dies.
        # which... again, we could do in this class.
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.borrow())
            stack.enter_context(infop.borrow(self.task))
            if rusage is not None:
                stack.enter_context(rusage.borrow(self.task))
            try:
                await rsyscall.near.waitid(self.task.sysif, self.near, infop.near, options,
                                           rusage.near if rusage else None)
            except ChildProcessError as e:
                raise ChildProcessError(e.errno, e.strerror, self.near) from None
        self.unread_siginfo = infop

    def parse_waitid_siginfo(self, siginfo: Siginfo) -> t.Optional[ChildEvent]:
        self.unread_siginfo = None
        if siginfo.pid == 0:
            return None
        else:
            event = ChildEvent.make_from_siginfo(siginfo)
            if event.died():
                self.mark_dead(event)
            return event

    # helpers
    async def read_siginfo(self) -> t.Optional[ChildEvent]:
        if self.unread_siginfo is None:
            raise Exception("no siginfo buf to read")
        else:
            siginfo = await self.unread_siginfo.read()
            return self.parse_waitid_siginfo(siginfo)

    async def read_event(self) -> ChildEvent:
        event = await self.read_siginfo()
        if event is None:
            raise Exception("expected an event, but siginfo buf didn't contain one")
        return event

class ThreadProcess(ChildProcess):
    def __init__(self, task: Task, near: rsyscall.near.Process,
                 used_stack: Pointer[Stack],
                 stack_data: Stack,
                 ctid: t.Optional[Pointer[FutexNode]],
                 tls: t.Optional[Pointer],
    ) -> None:
        super().__init__(task, near)
        self.used_stack = used_stack
        self.stack_data = stack_data
        self.ctid = ctid
        self.tls = tls

    def free_everything(self) -> None:
        # TODO don't know how to free the stack data...
        if self.used_stack.valid:
            self.used_stack.free()
        if self.ctid is not None and self.ctid.valid:
            self.ctid.free()
        if self.tls is not None and self.tls.valid:
            self.tls.free()

    def mark_dead(self, event: ChildEvent) -> None:
        self.free_everything()
        return super().mark_dead(event)

    def did_exec(self) -> ChildProcess:
        self.free_everything()
        return super().did_exec()


################################################################################
# Memory mappings

@dataclass
class MemoryMapping:
    task: Task
    near: rsyscall.near.MemoryMapping
    file: File

    async def munmap(self) -> None:
        await rsyscall.near.munmap(self.task.sysif, self.near)
