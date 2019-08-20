from __future__ import annotations
from dataclasses import dataclass
import abc
import gc
import rsyscall.far
import rsyscall.near
import trio
import typing as t
import logging
import contextlib
logger = logging.getLogger(__name__)

from rsyscall.fcntl import F
from rsyscall.sched import CLONE
from rsyscall.path import Path

T_fd = t.TypeVar('T_fd', bound='BaseFileDescriptor')
@dataclass(eq=False)
class BaseFileDescriptor:
    """A file descriptor accessed through some Task, with most FD-based syscalls as methods

    A FileDescriptor represents the ability to use some open file through some task.  When
    an open file is created by some task, the syscall will return a FileDescriptor which
    allows accessing that open file through that task. Pipes, sockets, and many other
    entities on Linux are represented as files.

    A FileDescriptor has many methods to make syscalls; most syscalls which take a file
    descriptor as their first argument are present as a method on FileDescriptor. These
    syscalls will be made through the Task in the FileDescriptor's `task` field.

    After we have opened the file and performed some operations on it, we can call the
    close method to immediately close the FileDescriptor and free its resources. The
    FileDescriptor will also be automatically closed in the background after the
    FileDescriptor has been garbage collected. Garbage collection should be relied on and
    preferred over context managers or explicit closing, which are both too inflexible for
    large scale resource management.

    If we want to access the file from another task, we may call the for_task method on
    the FileDescriptor, passing the other task from which we want to access the file.
    This will return another FileDescriptor referencing that file.  This will only work if
    the two tasks are in the same file descriptor table; that is typically the case for
    most scenarios and most kinds of threads. If the tasks are not in the same file
    descriptor table, more complicated methods must be used to pass the FileDescriptor to
    the other task; for example, CmsgSCMRights.

    Once we've called for_task at least once, we'll have multiple FileDescriptors all
    referencing the same file. Assuming the tasks have not exited, exec'd, or otherwise
    unshared their file descriptor table, these FileDescriptors will be sharing the same
    underlying near.FileDescriptor in the same file descriptor table. If that's the case,
    then we can no longer call the close method on any one FileDescriptor, because that
    would close the underlying near.FileDescriptor, and break the other FileDescriptors
    using it.

    Instead, we must use the invalidate method to invalidate just our FileDescriptor
    without affecting any others. Only when invalidate is called on the last
    FileDescriptor will the file be closed. We can also still rely on the garbage
    collector to close the underlying near.FileDescriptor once all the FileDescriptors
    using it have been garbage collected.

    If a task calls unshare(CLONE.FILES) to change its file descriptor table, all the
    FileDescriptors which access files through that task remain valid. Linux will copy all
    the file descriptors from the old file descriptor table to the new file descriptor
    table, keeping the same numbers. The FileDescriptors for that task will still be
    referencing the same file, but through different file descriptors in a new file
    descriptor table. Since the file descriptor numbers do not change, near.FileDescriptor
    will not change either, and no actual change is required in the FileDescriptors. See
    Task.unshare_files for more details.

    Garbage collection is currently run when we change file descriptor tables, as well as
    on-demand when run_fd_table_gc is run.

    """
    task: FileDescriptorTask
    near: rsyscall.near.FileDescriptor
    valid: bool = True

    def _make_fd_handle(self: T_fd, near: rsyscall.near.FileDescriptor) -> T_fd:
        return self.task.make_fd_handle(near)

    def _validate(self) -> None:
        if not self.valid:
            raise Exception("handle is no longer valid")

    def _invalidate(self) -> bool:
        """Invalidate this reference to this file descriptor

        Returns true if we removed the last reference, and are now responsible for closing the FD.

        """
        if self.valid:
            self.valid = False
            handles = self._remove_from_tracking()
            return len(handles) == 0
        else:
            return False

    async def invalidate(self) -> bool:
        """Invalidate this reference to this file descriptor, closing it if necessary

        Returns true if we removed the last reference, and closed the FD.

        We'll use the task inside the last file descriptor to be invalidated to actually
        do the close.
        """
        if self._invalidate():
            # we were the last handle for this fd, we should close it
            logger.debug("invalidating %s, no handles remaining, closing", self)
            await rsyscall.near.close(self.task.sysif, self.near)
            del fd_table_to_near_to_handles[self.task.fd_table][self.near]
            return True
        else:
            logger.debug("invalidating %s, some handles remaining", self)
            return False

    async def close(self) -> None:
        "Close this file descriptor if it's the only handle to it; throwing if there's other handles"
        if not self.is_only_handle():
            raise Exception("can't close this fd, there are handles besides this one to it")
        if not self.valid:
            raise Exception("can't close an invalid FD handle")
        closed = await self.invalidate()
        if not closed:
            raise Exception("for some reason, the fd wasn't closed; "
                            "maybe some race condition where there are still handles left around?")

    def for_task(self, task: FileDescriptorTask[T_fd]) -> T_fd:
        "Make another FileDescriptor referencing the same file but using `task` for syscalls"
        return task.make_fd_handle(self)

    @contextlib.contextmanager
    def borrow(self, task: FileDescriptorTask) -> t.Iterator[rsyscall.near.FileDescriptor]:
        "Validate that this FD can be accessed from this Task, and yield the near.FD to use for syscalls"
        # TODO we should be the only means of getting FD.near
        # TODO we should just set an in_use flag or something
        # oh argh, what about borrow_with, though?
        # hmm that's fine I guess... there's references inside...
        # ok, the thing is, we already can't move fds or pointers around
        # because we have references in memory
        # maybe borrowing should be another, more strong reference?
        # well, the point of this that we won't be freed during a syscall
        if self.task == task:
            yield self.near
        else:
            # note that we can't immediately change this to not use for_task,
            # because we need to get an FD which stays in the same fd table as task,
            # even if the task owning the FD we're borrowing switches fd tables
            borrowed = self.for_task(task)
            try:
                yield borrowed.near
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

    def maybe_copy(self: T_fd, task: FileDescriptorTask[T_fd]) -> T_fd:
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

    def move(self, task: FileDescriptorTask[T_fd]) -> T_fd:
        """Return the output of self.for_task(task), and also invalidate `self`.

        This is useful for more precisely expressing intent, if we don't intend to use
        `self` after getting the new FileDescriptor for the other task.

        This is also somewhat optimized relative to just calling self.for_task then
        calling self.invalidate; the latter call will have to be async, but this call
        doesn't have to be async, since we know we won't be invalidating the last handle.

        """
        new = self.for_task(task)
        self.valid = False
        handles = self._remove_from_tracking()
        if len(handles) == 0:
            raise Exception("We just made handle B from handle A, "
                            "so we know there are at least two handles; "
                            "but after removing handle A, there are no handles left. Huh?")
        return new

    def _get_global_handles(self) -> t.List[BaseFileDescriptor]:
        return fd_table_to_near_to_handles[self.task.fd_table][self.near]

    def is_only_handle(self) -> bool:
        self._validate()
        return len(self._get_global_handles()) == 1

    def _remove_from_tracking(self) -> t.List[BaseFileDescriptor]:
        self.task.fd_handles.remove(self)
        handles = self._get_global_handles()
        handles.remove(self)
        return handles

    def __del__(self) -> None:
        if self.valid:
            if len(self._remove_from_tracking()) == 0:
                logger.debug("leaked fd: %s", self)

    def __str__(self) -> str:
        return f"FD({self.task}, {self.near.number})"

    def __repr__(self) -> str:
        return f"FD({self.task}, {self.near.number}, valid={self.valid})"

    def as_proc_self_path(self) -> Path:
        num = self.near.number
        return Path(f"/proc/self/fd/{num}")

    async def dup2(self, newfd: T_fd) -> T_fd:
        return await self.dup3(newfd, 0)

    # oldfd has to be a valid file descriptor. newfd is not, technically, required to be
    # open, but that's the best practice for avoiding races, so we require it anyway here.
    async def dup3(self, newfd: T_fd, flags: int) -> T_fd:
        self._validate()
        if not newfd.is_only_handle():
            raise Exception("can't dup over newfd", newfd, "there are more handles to it than just ours")
        with newfd.borrow(self.task):
            if self.near == newfd.near:
                # dup3 fails if newfd == oldfd. I guess I'll just work around that.
                return newfd
            await rsyscall.near.dup3(self.task.sysif, self.near, newfd.near, flags)
            # newfd is left as a valid pointer to the new file descriptor
            return newfd

    async def copy_from(self, source: BaseFileDescriptor, flags=0) -> None:
        await source.dup3(self, flags)

    async def replace_with(self, source: BaseFileDescriptor, flags=0) -> None:
        await source.dup3(self, flags)
        await source.invalidate()

fd_table_to_near_to_handles: t.Dict[rsyscall.far.FDTable, t.Dict[rsyscall.near.FileDescriptor, t.List[BaseFileDescriptor]]] = {}
fd_table_to_task: t.Dict[rsyscall.far.FDTable, t.List[FileDescriptorTask]] = {}

async def run_fd_table_gc(fd_table: rsyscall.far.FDTable) -> None:
    if fd_table not in fd_table_to_task:
        # this is an fd table that has never had active tasks;
        # probably we called run_fd_table_gc on an exited task
        return
    gc.collect()
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

class FileDescriptorTask(t.Generic[T_fd], rsyscall.far.Task):
    def __post_init__(self) -> None:
        super().__post_init__()
        self.fd_handles: t.List[T_fd] = []
        self.manipulating_fd_table = False
        self._setup_fd_table_handles()
        self._add_to_active_fd_table_tasks()

    # for extensibility
    @abc.abstractmethod
    def _file_descriptor_constructor(self, fd: rsyscall.near.FileDescriptor) -> T_fd: ...

    def _make_fd_handle_from_near(self, fd: rsyscall.near.FileDescriptor) -> T_fd:
        if self.manipulating_fd_table:
            raise Exception("can't make a new FD handle while manipulating_fd_table==True")
        handle = self._file_descriptor_constructor(fd)
        logger.debug("made handle: %s", self)
        self.fd_handles.append(handle)
        fd_table_to_near_to_handles[self.fd_table].setdefault(fd, []).append(handle)
        return handle

    def make_fd_handle(self, fd: t.Union[rsyscall.near.FileDescriptor,
                                         BaseFileDescriptor]) -> T_fd:
        if isinstance(fd, rsyscall.near.FileDescriptor):
            near = fd
        elif isinstance(fd, BaseFileDescriptor):
            fd._validate()
            if fd.task.fd_table == self.fd_table:
                near = fd.near
            else:
                raise rsyscall.far.FDTableMismatchError(fd.task.fd_table, self.fd_table)
        else:
            raise Exception("bad fd type", fd, type(fd))
        return self._make_fd_handle_from_near(near)

    def _add_to_active_fd_table_tasks(self) -> None:
        fd_table_to_task.setdefault(self.fd_table, []).append(self)

    def _setup_fd_table_handles(self) -> None:
        near_to_handles = fd_table_to_near_to_handles.setdefault(self.fd_table, {})
        for handle in self.fd_handles:
            near_to_handles.setdefault(handle.near, []).append(handle)

    def _make_fresh_fd_table(self) -> None:
        self.fd_table = rsyscall.far.FDTable(self.near_process.id)
        self._setup_fd_table_handles()

    async def unshare_files(self) -> None:
        """Unshare this task's file descriptor table.

        When such an unshare is done, the new file descriptor table may contain file
        descriptors which were copied from the old file descriptor table but are not now
        referenced by any FileDescriptor. Likewise, the old file descriptor table may
        contain file descriptors which are no longer referenced by any FileDescriptor,
        since the FileDescriptors that referenced them were all for the task that unshared
        its table.  To remove such garbage, run_fd_table_gc is called for both the new and
        old fd tables after the unshare is complete.

        """
        if self.manipulating_fd_table:
            raise Exception("can't unshare_files while manipulating_fd_table==True")
        # do a GC now to improve efficiency when GCing both tables after the unshare
        gc.collect()
        await run_fd_table_gc(self.fd_table)
        self.manipulating_fd_table = True
        old_fd_table = self.fd_table
        self._make_fresh_fd_table()
        # each fd in the old table is also in the new table, possibly with no handles
        for fd in fd_table_to_near_to_handles[old_fd_table]:
            fd_table_to_near_to_handles[self.fd_table].setdefault(fd, [])
        self._add_to_active_fd_table_tasks()
        # perform the actual unshare
        await rsyscall.near.unshare(self.sysif, CLONE.FILES)
        self.manipulating_fd_table = False
        # We can only remove our handles from the handle lists after the unshare is done
        # and the fds are safely copied, because otherwise someone else running GC on the
        # old fd table would close our fds when they notice there are no more handles.
        old_near_to_handles = fd_table_to_near_to_handles[old_fd_table]
        for handle in self.fd_handles:
            old_near_to_handles[handle.near].remove(handle)
        await run_fd_table_gc(old_fd_table)
        await run_fd_table_gc(self.fd_table)
