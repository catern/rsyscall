"""Classes which own resources and provide the main syscall interfaces

We have several resource-owning classes in this module: FileDescriptor, Pointer, Process,
MemoryMapping, etc.

In the analogy to near and far pointers, they are like a near pointer plus a segment
register. A more useful analogy is to "handles" from classic Mac OS/PalmOS/16-bit Windows
memory management. Like handles, these classes are locked on use with the "borrow" context
manager, and they are weakly "relocatable", in that they continue to be valid as the
task's segment ids (namespaces) change. See:
https://en.wikipedia.org/wiki/Mac_OS_memory_management

However, unlike the MacOS handles that are the origin of the name of this module, these
resource-owning classes are garbage collected. Garbage collection should be relied on and
preferred over context managers or explicit closing, which are both far too inflexible for
large scale resource management.

"""
from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import rsyscall.far
import rsyscall.near
from rsyscall.far import File
import os
import typing as t
import logging
import contextlib
from rsyscall.command import Command
from rsyscall.handle.fd import FileDescriptorTask, BaseFileDescriptor, FDTable
from rsyscall.handle.pointer import Pointer, WrittenPointer, ReadablePointer, LinearPointer
from rsyscall.handle.process import Process, ChildProcess, ThreadProcess, ProcessTask
from rsyscall.near.sysif import UnusableSyscallInterface
logger = logging.getLogger(__name__)

from rsyscall.sched import CLONE, Stack, _unshare
from rsyscall.signal import Siginfo
from rsyscall.fcntl import AT, F, FD
from rsyscall.path import Path
from rsyscall.unistd import SEEK, ArgList, Pipe, OK
from rsyscall.unistd.exec import _execve, _execveat, _exit
from rsyscall.linux.futex import RobustListHead, FutexNode
from rsyscall.sys.wait import W

from rsyscall.fcntl        import               FcntlFileDescriptor
from rsyscall.sys.eventfd  import EventfdTask,  EventFileDescriptor
from rsyscall.sys.timerfd  import TimerfdTask,  TimerFileDescriptor
from rsyscall.sys.epoll    import EpollTask,    EpollFileDescriptor
from rsyscall.sys.inotify  import InotifyTask,  InotifyFileDescriptor
from rsyscall.sys.signalfd import SignalfdTask, SignalFileDescriptor
from rsyscall.sys.mman     import MemoryMappingTask, MappableFileDescriptor
from rsyscall.sys.stat     import               StatFileDescriptor
from rsyscall.signal       import SignalTask
from rsyscall.sys.socket   import SocketTask,   SocketFileDescriptor
from rsyscall.sys.ioctl    import               IoctlFileDescriptor
from rsyscall.linux.dirent import               GetdentsFileDescriptor
from rsyscall.linux.futex  import FutexTask
from rsyscall.linux.memfd  import MemfdTask
from rsyscall.sys.uio      import               UioFileDescriptor
from rsyscall.unistd       import FSTask,       FSFileDescriptor
from rsyscall.unistd.pipe  import PipeTask
from rsyscall.unistd.cwd   import CWDTask
from rsyscall.unistd.credentials import CredentialsTask
from rsyscall.unistd.io    import IOFileDescriptor, SeekableFileDescriptor
from rsyscall.sys.capability import CapabilityTask
from rsyscall.sys.prctl    import PrctlTask
from rsyscall.sys.mount    import MountTask
from rsyscall.sys.resource import ResourceTask
from rsyscall.sched        import SchedTask

# re-exported
from rsyscall.sched import Borrowable

__all__ = [
    "FileDescriptor", "FDTable", "BaseFileDescriptor",
    "Pointer", "WrittenPointer", "ReadablePointer", "LinearPointer",
    "Process", "ChildProcess", "ThreadProcess",
    "Task",
]


################################################################################
# FileDescriptor
T = t.TypeVar('T')
@dataclass(eq=False)
class FileDescriptor(
        EventFileDescriptor, TimerFileDescriptor, EpollFileDescriptor,
        InotifyFileDescriptor, SignalFileDescriptor,
        IoctlFileDescriptor, GetdentsFileDescriptor, UioFileDescriptor,
        SeekableFileDescriptor, IOFileDescriptor,
        FSFileDescriptor,
        SocketFileDescriptor,
        MappableFileDescriptor,
        StatFileDescriptor,
        FcntlFileDescriptor,
        BaseFileDescriptor,
):
    """A file descriptor accessed through some `Task`, with FD-based syscalls as methods

    A `FileDescriptor` represents the ability to use some open file through some `Task`.
    When an open file is created by a syscall in some `Task`,
    the syscall will return a `FileDescriptor` which allows accessing that open file through that `Task`.

    A `FileDescriptor` has many methods to make syscalls;
    most syscalls which take a file descriptor as their first argument are present as a method on `FileDescriptor`.
    These syscalls will be made through the `Task` in the FileDescriptor's `task` field.

    Since there are so many syscalls,
    this class is built by inheriting from many other purpose specific `FooFileDescriptor` classes,
    which in turn all inherit from `BaseFileDescriptor`.

    After we have opened the file and performed some operations on it,
    we can call `close` to immediately close the FileDescriptor and free its resources.
    The FileDescriptor will also be automatically closed in the background
    after the FileDescriptor has been garbage collected.
    Garbage collection should be relied on and preferred over context managers or explicit closing,
    which are both too inflexible for large scale resource management.
    Garbage collection is currently run when we change file descriptor tables,
    as well as on-demand if the user calls `FileDescriptorTask.run_fd_table_gc`.

    We can use `inherit` to copy a FileDescriptor into a task which inherited file descriptors from a parent,
    and `for_task` to copy a FileDescriptor into tasks sharing the same file descriptor table.
    We can also use more complicated methods, such as `rsyscall.sys.socket.CmsgSCMRights`,
    to copy file descriptors without inheritance or a shared file descriptor table.

    """
    __slots__ = ()
    task: Task

    def as_proc_path(self) -> Path:
        """Return the /proc/{pid}/fd/{num} path pointing to this FD.

        This should be used with care, but it's sometimes useful for programs
        which accept paths instead of file descriptors.

        """
        pid = self.task.process.near.id
        num = self.near.number
        return Path(f"/proc/{pid}/fd/{num}")

    async def disable_cloexec(self) -> None:
        "Unset the `FD.CLOEXEC` flag so this file descriptor can be inherited"
        # TODO this doesn't make any sense. we shouldn't allow cloexec if there are multiple people in our fd table;
        # whether or not there are multiple handles to the fd is irrelevant.
        if not self.is_only_handle():
            raise Exception("shouldn't disable cloexec when there are multiple handles to this fd")
        await self.fcntl(F.SETFD, 0)

    async def enable_cloexec(self) -> None:
        "Set the `FD.CLOEXEC` flag so this file descriptor can't be inherited"
        await self.fcntl(F.SETFD, FD.CLOEXEC)

    async def as_argument(self) -> int:
        "`disable_cloexec`, then return this `FileDescriptor` as an integer; useful when passing the FD as an argument"
        await self.disable_cloexec()
        return int(self)

    async def __aenter__(self) -> FileDescriptor:
        return self

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        if self.valid:
            return f"FD({self.task}, {self.near.number})"
        else:
            return f"FD({self.task}, {self.near.number}, valid=False)"


################################################################################
# Task

class Task(
        EventfdTask[FileDescriptor], TimerfdTask[FileDescriptor], EpollTask[FileDescriptor],
        InotifyTask[FileDescriptor], SignalfdTask[FileDescriptor],
        MemfdTask[FileDescriptor],
        FSTask[FileDescriptor],
        SocketTask[FileDescriptor],
        PipeTask,
        MemoryMappingTask, CWDTask,
        FileDescriptorTask[FileDescriptor],
        CapabilityTask, PrctlTask, MountTask,
        CredentialsTask,
        ProcessTask,
        SchedTask,
        ResourceTask,
        FutexTask,
        SignalTask, rsyscall.far.Task,
):
    """A Linux process context under our control, ready for syscalls

    Since there are many different syscalls we could make,
    this class is built by inheriting from many other purpose specific "Task" classes,
    which in turn all inherit from the base `rsyscall.far.Task`.

    This is named after the kernel struct, "struct task", associated with each process.

    """
    def __init__(self,
                 process: t.Union[rsyscall.near.Process, Process],
                 fd_table: FDTable,
                 address_space: rsyscall.far.AddressSpace,
                 pidns: rsyscall.far.PidNamespace,
    ) -> None:
        super().__init__(
            UnusableSyscallInterface(),
            t.cast(rsyscall.near.Process, process), fd_table, address_space, pidns,
        )

    def _file_descriptor_constructor(self, fd: rsyscall.near.FileDescriptor) -> FileDescriptor:
        # for extensibility
        return FileDescriptor(self, fd, True)

    def _make_fresh_address_space(self) -> None:
        self.address_space = rsyscall.far.AddressSpace(self.process.near.id)

    async def unshare(self, flags: CLONE) -> None:
        if flags & CLONE.FILES:
            await self.unshare_files()
            flags ^= CLONE.FILES
        if flags:
            await _unshare(self.sysif, flags)

    async def setns_user(self, fd: FileDescriptor) -> None:
        # can't setns to a user namespace while sharing CLONE_FS
        await self.unshare(CLONE.FS)
        await self.setns(fd, CLONE.NEWUSER)

    async def execveat(self, fd: t.Optional[FileDescriptor],
                       pathname: WrittenPointer[t.Union[str, os.PathLike]],
                       argv: WrittenPointer[ArgList],
                       envp: WrittenPointer[ArgList],
                       flags: AT=AT.NONE,
                       command: Command=None,
    ) -> None:
        with contextlib.ExitStack() as stack:
            if fd:
                fd_n: t.Optional[rsyscall.near.FileDescriptor] = stack.enter_context(fd.borrow(self))
            else:
                fd_n = None
            stack.enter_context(pathname.borrow(self))
            argv.check_address_space(self)
            envp.check_address_space(self)
            for arg in [*argv.value, *envp.value]:
                stack.enter_context(arg.borrow(self))
            self.manipulating_fd_table = True
            try:
                await _execveat(self.sysif, fd_n, pathname.near, argv.near, envp.near, flags)
            except OSError as exn:
                exn.filename = (fd, pathname.value)
                raise
            finally:
                self.manipulating_fd_table = False
            self._make_fresh_fd_table()
            self._make_fresh_address_space()
            if isinstance(self.process, ChildProcess):
                self.process.did_exec(command)
        await self.sysif.close_interface()

    async def execve(self, filename: WrittenPointer[t.Union[str, os.PathLike]],
                     argv: WrittenPointer[ArgList],
                     envp: WrittenPointer[ArgList],
                     command: Command=None,
    ) -> None:
        filename.check_address_space(self)
        argv.check_address_space(self)
        envp.check_address_space(self)
        for arg in [*argv.value, *envp.value]:
            arg.check_address_space(self)
        self.manipulating_fd_table = True
        try:
            await _execve(self.sysif, filename.near, argv.near, envp.near)
        except OSError as exn:
            exn.filename = filename.value
            raise
        self.manipulating_fd_table = False
        self._make_fresh_fd_table()
        self._make_fresh_address_space()
        if isinstance(self.process, ChildProcess):
            self.process.did_exec(command)
        await self.sysif.close_interface()

    async def exit(self, status: int) -> None:
        self.manipulating_fd_table = True
        await _exit(self.sysif, status)
        self.manipulating_fd_table = False
        self._make_fresh_fd_table()
        # close the syscall interface; we don't have to do this since it'll be
        # GC'd, but maybe we want to be tidy in advance.
        await self.sysif.close_interface()
