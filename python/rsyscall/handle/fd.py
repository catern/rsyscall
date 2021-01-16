"""Fundamental FD ownership and lifecycle

We should probably move this to unistd.fd; after all, we define the
_close system call in this module, as part of the fundamental
lifecycle of an FD.

"""

from __future__ import annotations
from dataclasses import dataclass
from weakref import WeakSet
import itertools
import abc
import gc
import rsyscall.far
import rsyscall.near
from rsyscall.near.sysif import SyscallHangup, SyscallInterface
from rsyscall.sys.syscall import SYS
import trio
import typing as t
import logging
import contextlib
logger = logging.getLogger(__name__)

from rsyscall.sched import CLONE, _unshare

T_fd = t.TypeVar('T_fd', bound='BaseFileDescriptor')
@dataclass(eq=False)
class BaseFileDescriptor:
    """A file descriptor accessed through some `Task`

    This is an rsyscall-internal base class,
    which other `FileDescriptor` objects inherit from for core lifecycle methods.
    See `FileDescriptor` for more information.

    """
    __slots__ = ('task', 'near', 'valid')
    task: FileDescriptorTask
    near: rsyscall.near.FileDescriptor
    valid: bool

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
            fd_table = self.task.fd_table
            del fd_table.near_to_handles[self.near]
            await fd_table._close_fd(self.task, self.near)
            return True
        else:
            logger.debug("invalidating %s, some handles remaining", self)
            return False

    async def close(self) -> None:
        """Close this file descriptor if it's the only handle to it; throwing if there's other handles

        manpage: close(2)
        """
        if not self.is_only_handle():
            raise Exception("can't close this fd", self, "there are handles besides this one to it",
                            self._get_global_handles())
        if not self.valid:
            raise Exception("can't close an invalid FD handle")
        closed = await self.invalidate()
        if not closed:
            raise Exception("for some reason, the fd wasn't closed; "
                            "maybe some race condition where there are still handles left around?")

    def inherit(self, task: FileDescriptorTask[T_fd]) -> T_fd:
        """Make another FileDescriptor referencing the same file but using `task`, which inherited this FD, for syscalls

        Whenever we call `clone` (without passing `CLONE.FILES`),
        the file descriptors in the parent process are copied to the child process;
        this is tracked in rsyscall, and we can call `inherit` on any parent `FileDescriptor`
        to get a handle for the copy in the child.

        """
        return task.inherit_fd(self)

    def for_task(self, task: FileDescriptorTask[T_fd]) -> T_fd:
        """Make a new handle for the same FD, but using `task`, in the same FD table, for syscalls

        Two tasks in the same file descriptor table can be created by calling `clone` with `CLONE.FILES`.

        Once we call this method, we'll have multiple handles for a single file descriptor,
        in a single file descriptor table.
        We won't be able to use `close` to close the FD, since that would break other handles;
        we'll need to use `invalidate` instead.
        (Or, we can just rely on garbage collection.)

        If we want to access the file from another task, we may call the for_task method on
        the FileDescriptor, passing the other task from which we want to access the file.
        This will return another FileDescriptor referencing that file.  This will only work if
        the two tasks are in the same file descriptor table; that is typically the case for
        most scenarios and most kinds of threads. .

        """
        self._validate()
        if self.task.fd_table != task.fd_table:
            raise rsyscall.far.FDTableMismatchError(self.task.fd_table, task.fd_table)
        return task._make_fd_handle_from_near(self.near)

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

    def _get_global_handles(self) -> WeakSet[BaseFileDescriptor]:
        return self.task.fd_table.near_to_handles[self.near]

    def is_only_handle(self) -> bool:
        self._validate()
        return len(self._get_global_handles()) == 1

    def _remove_from_tracking(self) -> WeakSet[BaseFileDescriptor]:
        self.task.fd_handles.remove(self)
        handles = self._get_global_handles()
        handles.remove(self)
        return handles

    def __int__(self) -> int:
        return self.near.number

async def _close(sysif: SyscallInterface, fd: rsyscall.near.FileDescriptor) -> None:
    try:
        await sysif.syscall(SYS.close, fd)
    except OSError as e:
        e.filename = fd
        raise

class FDTable(rsyscall.far.FDTable):
    def __init__(self, creator_pid: int, parent: FDTable=None) -> None:
        super().__init__(creator_pid)
        self.near_to_handles: t.Dict[rsyscall.near.FileDescriptor, WeakSet[BaseFileDescriptor]] = {}
        self.tasks: WeakSet[FileDescriptorTask] = WeakSet([])
        if parent:
            self.inherited: WeakSet[BaseFileDescriptor] = WeakSet(
                itertools.chain(itertools.chain.from_iterable(parent.near_to_handles.values()),
                                parent.inherited)
            )
        else:
            self.inherited = WeakSet()

    def remove_inherited(self) -> None:
        self.inherited = WeakSet()

    def _get_task_in_table(self) -> t.Optional[FileDescriptorTask]:
        for task in list(self.tasks):
            if task.fd_table is not self:
                self.tasks.remove(task)
            elif task.manipulating_fd_table:
                # skip tasks currently changing fd table
                pass
            else:
                return task
        return None

    async def _close_fd(self, task: FileDescriptorTask, fd: rsyscall.near.FileDescriptor) -> None:
        try:
            # TODO we don't have to block here, we can just send off the close without waiting for it,
            # because you aren't supposed to retry close on error.
            # well, except when we actually want to give the user the chance to see the error from close.
            await _close(task.sysif, fd)
        except SyscallHangup:
            # closing the fd through this task went wrong
            # TODO we should mark this task as dead and fall back to later tasks in the list if
            # we fail due to a SyscallInterface-level error; that might happen if, say, this is
            # some decrepit task where we closed the syscallinterface but didn't exit the task.
            assert fd not in self.near_to_handles, f"fd {fd} was somehow reopened before it was actually closed"
            # put the fd back, some other task will close it
            self.near_to_handles[fd] = WeakSet()

    async def gc_using_task(self, task: FileDescriptorTask) -> None:
        gc.collect()
        async with trio.open_nursery() as nursery:
            # take a snapshot of near_to_handles so we can mutate it while iterating
            for fd, handles in list(self.near_to_handles.items()):
                if not handles:
                    # we immediately take responsibility for closing this fd, so our close
                    # attempts don't collide with others
                    del self.near_to_handles[fd]
                    logger.debug("gc for %s: starting close fd for %s", self, fd)
                    nursery.start_soon(self._close_fd, task, fd)

    async def run_gc(self) -> None:
        task = self._get_task_in_table()
        if task is not None:
            await self.gc_using_task(task)

class FileDescriptorTask(rsyscall.far.Task, t.Generic[T_fd]):
    def __init__(self,
                 sysif: rsyscall.near.SyscallInterface,
                 near_process: rsyscall.near.Process,
                 fd_table: FDTable,
                 address_space: rsyscall.far.AddressSpace,
                 pidns: rsyscall.far.PidNamespace,
    ) -> None:
        if not isinstance(fd_table, FDTable):
            raise Exception("fd_table", fd_table, "needs to be an", FDTable,
                            "to work with a", FileDescriptorTask)
        self.fd_table: FDTable
        super().__init__(sysif, near_process, fd_table, address_space, pidns)

    def __post_init__(self) -> None:
        super().__post_init__()
        self.fd_handles: WeakSet[T_fd] = WeakSet()
        self.manipulating_fd_table = False
        self._add_to_active_fd_table_tasks()

    # for extensibility
    @abc.abstractmethod
    def _file_descriptor_constructor(self, fd: rsyscall.near.FileDescriptor) -> T_fd: ...

    def _make_fd_handle_from_near(self, fd: rsyscall.near.FileDescriptor) -> T_fd:
        if self.manipulating_fd_table:
            raise Exception("can't make a new FD handle while manipulating_fd_table==True")
        handle = self._file_descriptor_constructor(fd)
        logger.debug("%s: made handle %s from %s", self, handle, fd)
        self.fd_handles.add(handle)
        self.fd_table.near_to_handles.setdefault(fd, WeakSet()).add(handle)
        return handle

    def make_fd_handle(self, fd: rsyscall.near.FileDescriptor) -> T_fd:
        """Make a `FileDescriptor` referencing `fd`, which is currently unknown to rsyscall

        This is an unsafe operation: Since `rsyscall.near.FileDescriptor` is just a fancy `int`, we
        could use this to create handles for FDs which don't exist, or which are already being
        managed by others outside rsyscall. So use this with care.

        If this FD was inherited from a non-rsyscall parent process, you probably want to call
        `rsyscall.FileDescriptor.enable_cloexec` afterwards.

        """
        if fd in self.fd_table.near_to_handles:
            raise Exception("This fd is already known to us", fd)
        return self._make_fd_handle_from_near(fd)

    def inherit_fd(self, fd: BaseFileDescriptor) -> T_fd:
        """Make another FileDescriptor referencing `fd`, which we inherited, using this task for syscalls

        Whenever we call `clone` (without passing `CLONE.FILES`),
        the file descriptors in the parent process are copied to the child process;
        this is tracked in rsyscall, and we can call `inherit_fd` on any `FileDescriptor` in the parent process
        to get a handle for the copy of the file descriptor in the child.

        This same call also works if the two tasks are in the same file descriptor table, for convenience.

        """
        fd._validate()
        if fd.task.fd_table == self.fd_table:
            # let's allow "inheriting" fds that are already in.. the right fd table?
            # cuz... that way we can treat the case where we unshare and where we don't, identically
            # right? yes. it has to be the samed fd table, not the same task,
            # because the fds we're inheriting aren't in the same task.
            return self._make_fd_handle_from_near(fd.near)
        elif fd in self.fd_table.inherited:
            return self._make_fd_handle_from_near(fd.near)
        else:
            raise Exception("tried to inherit non-inherited fd", fd)

    def _add_to_active_fd_table_tasks(self) -> None:
        self.fd_table.tasks.add(self)

    def _make_fresh_fd_table(self) -> FDTable:
        """Make a new fd table that is a copy of the old one

        This is called by unshare_files, exec, and exit.

        """
        self.fd_table = FDTable(self.near_process.id)
        near_to_handles = self.fd_table.near_to_handles
        for handle in self.fd_handles:
            if handle.near not in near_to_handles:
                near_to_handles[handle.near] = WeakSet()
            near_to_handles[handle.near].add(handle)
        return self.fd_table

    async def run_fd_table_gc(self, use_self: bool=True) -> None:
        if use_self:
            await self.fd_table.gc_using_task(self)
        else:
            await self.fd_table.run_gc()

    async def unshare_files(self) -> None:
        """Unshare this task's file descriptor table.

        When such an unshare is done, the new file descriptor table may contain file
        descriptors which were copied from the old file descriptor table but are not now
        referenced by any `FileDescriptor`. Likewise, the old file descriptor table may
        contain file descriptors which are no longer referenced by any `FileDescriptor`,
        since the `FileDescriptor`s that referenced them were all for the task that unshared
        its table.  To remove such garbage, run_fd_table_gc is called for both the new and
        old fd tables after the unshare is complete.

        All the `FileDescriptor`s which access files through the task will remain valid.
        Linux will copy all the file descriptors from the old file descriptor table to the new file descriptor table,
        keeping them at the same numbers.
        The `FileDescriptor`s for the task will still be referencing the same file,
        through different file descriptors, which happen to have the same file descriptor *numbers*,
        in a new file descriptor table.
        Since the file descriptor numbers do not change, `near.FileDescriptor` will not change either,
        and no actual change is required in the `FileDescriptor`s.

        """
        if self.manipulating_fd_table:
            raise Exception("can't unshare_files while manipulating_fd_table==True")
        # do a GC now to improve efficiency when GCing both tables after the unshare
        gc.collect()
        old_fd_table = self.fd_table
        await old_fd_table.gc_using_task(self)
        self.manipulating_fd_table = True
        new_fd_table = self._make_fresh_fd_table()
        self._add_to_active_fd_table_tasks()
        # perform the actual unshare
        await _unshare(self.sysif, CLONE.FILES)
        # Each fd in the old table in the old table is also in the new table; this includes unwanted
        # fds that had handles in the old table and now don't have any handles.  Various race
        # conditions make garbage collecting those unwanted fds quite difficult, and ultimately
        # impossible.
        # The right way to close those unwanted fds is to, after the unshare, temporarily unset
        # CLOEXEC on the fds that we want to preserve, then close all CLOEXEC fds.  But
        # unfortunately there's no cheap way to close all CLOEXC fds.
        # So, instead, we just let the unwanted fds leak into the new table.  Almost all threads that call
        # unshare_files will call exec soon after, which will handle closing all CLOEXEC fds for us,
        # and so the leaked unwanted fds will be closed.
        # Concretely, we'll only create handles in the new table for the fds that this task owns, so
        # only those fds are involved in garbage collection; that handle-creation happened in
        # _make_fresh_fd_table.
        # TODO add a syscall to close all CLOEXEC fds, and call it here with appropriate setup
        self.manipulating_fd_table = False
        # We can only remove our handles from the handle lists after the unshare is done
        # and the fds are safely copied, because otherwise someone else running GC on the
        # old fd table would close our fds when they notice there are no more handles.
        for handle in self.fd_handles:
            old_fd_table.near_to_handles[handle.near].remove(handle)
        # GC the old fd table to delete any fds that are no longer referenced by our handles.
        await old_fd_table.run_gc()
        # GC the new table just to make sure that GC works; this should be a no-op, but we might
        # have messed something up.
        await new_fd_table.gc_using_task(self)
