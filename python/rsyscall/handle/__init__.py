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
from rsyscall.handle.fd import FileDescriptorTask, BaseFileDescriptor
from rsyscall.handle.pointer import Pointer, WrittenPointer
from rsyscall.handle.process import Process, ChildProcess, ThreadProcess
logger = logging.getLogger(__name__)

from rsyscall.sched import CLONE, Stack
from rsyscall.signal import Siginfo
from rsyscall.fcntl import AT, F, O
from rsyscall.path import Path
from rsyscall.unistd import SEEK, Arg, ArgList, Pipe, OK
from rsyscall.linux.futex import RobustListHead, FutexNode
from rsyscall.sys.wait import W

from rsyscall.sys.eventfd  import EventfdTask,  EventFileDescriptor
from rsyscall.sys.timerfd  import TimerfdTask,  TimerFileDescriptor
from rsyscall.sys.epoll    import EpollTask,    EpollFileDescriptor
from rsyscall.sys.inotify  import InotifyTask,  InotifyFileDescriptor
from rsyscall.sys.signalfd import SignalfdTask, SignalFileDescriptor
from rsyscall.sys.memfd    import MemfdTask
from rsyscall.sys.mman     import MemoryMappingTask, MappableFileDescriptor
from rsyscall.signal       import SignalTask
from rsyscall.sys.socket   import SocketTask,   SocketFileDescriptor
from rsyscall.sys.ioctl    import               IoctlFileDescriptor
from rsyscall.linux.dirent import               GetdentsFileDescriptor
from rsyscall.sys.uio      import               UioFileDescriptor
from rsyscall.unistd       import FSTask,       FSFileDescriptor
from rsyscall.unistd.pipe  import PipeTask
from rsyscall.unistd.cwd   import CWDTask
from rsyscall.unistd.credentials import CredentialsTask
from rsyscall.unistd.io    import IOFileDescriptor, SeekableFileDescriptor
from rsyscall.sys.capability import CapabilityTask
from rsyscall.sys.prctl    import PrctlTask
from rsyscall.sys.mount    import MountTask

# re-exported
from rsyscall.sched import Borrowable
from rsyscall.sys.mman import MemoryMapping



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
        BaseFileDescriptor,
):
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
    def __init__(self, task: Task, near: rsyscall.near.FileDescriptor) -> None:
        super().__init__(task, near)
        self.task: Task = task

    def as_proc_path(self) -> Path:
        pid = self.task.process.near.id
        num = self.near.number
        return Path(f"/proc/{pid}/fd/{num}")

    async def disable_cloexec(self) -> None:
        # TODO this doesn't make any sense. we shouldn't allow cloexec if there are multiple people in our fd table;
        # whether or not there are multiple handles to the fd is irrelevant.
        if not self.is_only_handle():
            raise Exception("shouldn't disable cloexec when there are multiple handles to this fd")
        await self.fcntl(F.SETFD, 0)

    async def as_argument(self) -> int:
        await self.disable_cloexec()
        return int(self.near)

    async def fcntl(self, cmd: F, arg: t.Optional[int]=None) -> int:
        self._validate()
        return (await rsyscall.near.fcntl(self.task.sysif, self.near, cmd, arg))


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
        SignalTask, rsyscall.far.Task,
):
    # work around breakage in mypy - it doesn't understand dataclass inheritance
    # TODO delete this
    def __init__(self,
                 sysif: rsyscall.near.SyscallInterface,
                 process: t.Union[rsyscall.near.Process, Process],
                 fd_table: rsyscall.far.FDTable,
                 address_space: rsyscall.far.AddressSpace,
                 pidns: rsyscall.far.PidNamespace,
    ) -> None:
        self.sysif = sysif
        if isinstance(process, Process):
            self.near_process = process.near
            self.process = process
            self.parent_task: t.Optional[rsyscall.far.Task] = process.task
        else:
            self.near_process = process
            self.process = Process(self, process)
            self.parent_task = None
        self.fd_table = fd_table
        self.address_space = address_space
        self.pidns = pidns
        self.alive = True
        self.__post_init__()

    def _file_descriptor_constructor(self, fd: rsyscall.near.FileDescriptor) -> FileDescriptor:
        # for extensibility
        return FileDescriptor(self, fd)

    def __post_init__(self) -> None:
        super().__post_init__()

    def make_path_from_bytes(self, path: t.Union[str, bytes]) -> Path:
        return Path(os.fsdecode(path))

    def make_path_handle(self, path: Path) -> Path:
        return path

    def _make_fresh_address_space(self) -> None:
        self.address_space = rsyscall.far.AddressSpace(self.process.near.id)

    async def unshare(self, flags: CLONE) -> None:
        if flags & CLONE.FILES:
            await self.unshare_files()
            flags ^= CLONE.FILES
        if flags:
            await rsyscall.near.unshare(self.sysif, flags)

    async def setns(self, fd: FileDescriptor, nstype: CLONE) -> None:
        with fd.borrow(self) as fd_n:
            await rsyscall.near.setns(self.sysif, fd_n, nstype)

    async def setns_user(self, fd: FileDescriptor) -> None:
        # can't setns to a user namespace while sharing CLONE_FS
        await self.unshare(CLONE.FS)
        await self.setns(fd, CLONE.NEWUSER)

    async def mkdir(self, path: WrittenPointer[Path], mode=0o755) -> None:
        with path.borrow(self) as path_n:
            await rsyscall.near.mkdirat(self.sysif, None, path_n, mode)

    async def unlink(self, path: WrittenPointer[Path]) -> None:
        with path.borrow(self) as path_n:
            await rsyscall.near.unlinkat(self.sysif, None, path_n, 0)

    async def rmdir(self, path: WrittenPointer[Path]) -> None:
        with path.borrow(self) as path_n:
            await rsyscall.near.unlinkat(self.sysif, None, path_n, AT.REMOVEDIR)

    async def link(self, oldpath: WrittenPointer[Path], newpath: WrittenPointer[Path]) -> None:
        with oldpath.borrow(self) as oldpath_n:
            with newpath.borrow(self) as newpath_n:
                await rsyscall.near.linkat(self.sysif, None, oldpath_n, None, newpath_n, 0)

    async def rename(self, oldpath: WrittenPointer[Path], newpath: WrittenPointer[Path]) -> None:
        with oldpath.borrow(self) as oldpath_n:
            with newpath.borrow(self) as newpath_n:
                await rsyscall.near.renameat2(self.sysif, None, oldpath_n, None, newpath_n, 0)

    async def symlink(self, target: WrittenPointer, linkpath: WrittenPointer[Path]) -> None:
        with target.borrow(self) as target_n:
            with linkpath.borrow(self) as linkpath_n:
                await rsyscall.near.symlinkat(self.sysif, target_n, None, linkpath_n)

    async def waitid(self, options: W, infop: Pointer[Siginfo],
                     *, rusage: t.Optional[Pointer[Siginfo]]=None) -> None:
        with infop.borrow(self) as infop_n:
            if rusage is None:
                await rsyscall.near.waitid(self.sysif, None, infop_n, options, None)
            else:
                with rusage.borrow(self) as rusage_n:
                    await rsyscall.near.waitid(self.sysif, None, infop_n, options, rusage_n)

    async def execve(self, filename: WrittenPointer[Path],
                     argv: WrittenPointer[ArgList],
                     envp: WrittenPointer[ArgList],
                     flags: AT=AT.NONE) -> None:
        with contextlib.ExitStack() as stack:
            stack.enter_context(filename.borrow(self))
            for arg in [*argv.value, *envp.value]:
                stack.enter_context(arg.borrow(self))
            self.manipulating_fd_table = True
            try:
                if flags == AT.NONE:
                    await rsyscall.near.execve(self.sysif, filename.near, argv.near, envp.near)
                else:
                    await rsyscall.near.execveat(self.sysif, None, filename.near, argv.near, envp.near, flags)
            except FileNotFoundError as exn:
                exn.filename = filename.value
                raise
            except NotADirectoryError as exn:
                exn.filename = filename.value
                raise
            self.manipulating_fd_table = False
            self._make_fresh_fd_table()
            self._make_fresh_address_space()
            if isinstance(self.process, ChildProcess):
                self.process.did_exec()

    async def exit(self, status: int) -> None:
        self.manipulating_fd_table = True
        await rsyscall.near.exit(self.sysif, status)
        self.manipulating_fd_table = False
        self._make_fresh_fd_table()
        await self.close_task()

    async def close_task(self):
        # close the syscall interface and kill the process; we don't have to do this since it'll be
        # GC'd, but maybe we want to be tidy in advance.
        self.alive = False
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
            stack_alloc_end = stack_alloc.near + stack_alloc.size()
            if stack_alloc_end != stack_data.near:
                raise Exception("the end of the stack allocation pointer", stack_alloc_end,
                                "and the beginning of the stack data pointer", stack_data.near,
                                "must be the same")
            stack.enter_context(stack_alloc.borrow(self))
            stack.enter_context(stack_data.borrow(self))
            ptid_n = self._borrow_optional(stack, ptid)
            ctid_n = self._borrow_optional(stack, ctid)
            newtls_n = self._borrow_optional(stack, newtls)
            process = await rsyscall.near.clone(self.sysif, flags, stack_data.near, ptid_n,
                                                ctid_n + ffi.offsetof('struct futex_node', 'futex') if ctid_n else None,
                                                newtls_n)
        # TODO the safety of this depends on no-one borrowing/freeing the stack in borrow __aexit__
        # should try to do this a bit more robustly...
        merged_stack = stack_alloc.merge(stack_data)
        return ThreadProcess(owning_task, process, merged_stack, stack_data.value, ctid, newtls)

    async def set_robust_list(self, head: WrittenPointer[RobustListHead]) -> None:
        with head.borrow(self):
            await rsyscall.near.set_robust_list(self.sysif, head.near, head.size())

    def _make_process(self, pid: int) -> Process:
        return Process(self, rsyscall.near.Process(pid))
