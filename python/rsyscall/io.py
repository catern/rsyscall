from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.epoll import EpollEvent, EpollEventMask, EPOLL_CLOEXEC
import rsyscall.epoll
import abc
import os
import typing as t
import trio
import signal
import sfork
from async_generator import asynccontextmanager
import logging
import fcntl
import errno
logger = logging.getLogger(__name__)

class SyscallInterface:
    async def pipe(self, flags=os.O_NONBLOCK) -> t.Tuple[int, int]: ...
    async def close(self, fd: int) -> None: ...
    # TODO add optional offset argument?
    # TODO figure out how to allow preadv2 flags?
    async def read(self, fd: int, count: int) -> bytes: ...
    async def write(self, fd: int, buf: bytes) -> int: ...
    async def dup2(self, oldfd: int, newfd: int) -> int: ...
    async def wait_readable(self, fd: int) -> None: ...
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int: ...
    async def exit(self, status: int) -> int: ...
    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> int: ...

    # epoll operations
    async def epoll_create(self, flags: int) -> int: ...
    async def epoll_ctl_add(self, epfd: int, fd: int, event: EpollEvent) -> None: ...
    async def epoll_ctl_mod(self, epfd: int, fd: int, event: EpollEvent) -> None: ...
    async def epoll_ctl_del(self, epfd: int, fd: int) -> None: ...
    async def epoll_wait(self, epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]: ...

    # we can do the same with ioctl
    # but not with prctl. what a mistake prctl is!
    async def fcntl(self, fd: int, cmd: int, arg: t.Union[bytes, int]=0) -> t.Union[bytes, int]:
        "This follows the same protocol as fcntl.fcntl."
        ...
    # for prctl we will have a separate method for each usage mode;
    # its interface is too diverse to do anything else and still abstract over the details of memory

class LocalSyscall(SyscallInterface):
    def __init__(self, wait_readable) -> None:
        self._wait_readable = wait_readable

    async def wait_readable(self, fd: int) -> None:
        logger.debug("wait_readable(%s)", fd)
        await self._wait_readable(fd)

    async def pipe(self, flags=os.O_CLOEXEC) -> t.Tuple[int, int]:
        logger.debug("pipe(%s)", flags)
        return os.pipe2(flags)

    async def close(self, fd: int) -> None:
        logger.debug("close(%d)", fd)
        return os.close(fd)

    # TODO allow setting offset?
    async def read(self, fd: int, count: int) -> bytes:
        logger.debug("read(%d, %d)", fd, count)
        return os.read(fd, count)

    async def write(self, fd: int, buf: bytes) -> int:
        logger.debug("write(%d, len(buf) == %d)", fd, len(buf))
        return os.write(fd, buf)

    async def dup2(self, oldfd: int, newfd: int) -> int:
        logger.debug("dup2(%d, %d)", oldfd, newfd)
        os.dup2(oldfd, newfd)
        return newfd

    # TODO support setting child_stack so we can create threads
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int:
        logger.debug("clone(%d, %s)", flags, deathsig)
        if deathsig is not None:
            flags |= deathsig
        return sfork.clone(flags)

    async def exit(self, status: int) -> int:
        logger.debug("exit(%d)", status)
        return sfork.exit(status)

    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> int:
        logger.debug("execveat(%s)", path)
        return sfork.execveat(dirfd, path, argv, envp, flags)

    async def epoll_create(self, flags: int) -> int:
        logger.debug("epoll_create(%s)", flags)
        return rsyscall.epoll.epoll_create(flags)

    async def epoll_ctl_add(self, epfd: int, fd: int, event: EpollEvent) -> None:
        logger.debug("epoll_ctl_add(%d, %d, %s)", epfd, fd, event)
        rsyscall.epoll.epoll_ctl_add(epfd, fd, event)

    async def epoll_ctl_mod(self, epfd: int, fd: int, event: EpollEvent) -> None:
        logger.debug("epoll_ctl_mod(%d, %d, %s)", epfd, fd, event)
        rsyscall.epoll.epoll_ctl_mod(epfd, fd, event)

    async def epoll_ctl_del(self, epfd: int, fd: int) -> None:
        logger.debug("epoll_ctl_del(%d, %d)", epfd, fd)
        rsyscall.epoll.epoll_ctl_del(epfd, fd)

    async def epoll_wait(self, epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]:
        logger.debug("epoll_wait(%d, maxevents=%d, timeout=%d)", epfd, maxevents, timeout)
        return rsyscall.epoll.epoll_wait(epfd, maxevents, timeout)

    # should we pull the file status flags when we create fhe file?
    # yyyyes theoretically.
    # should we store it in the FileDescriptor?
    # hah, no, we should have a FileObject...
    async def fcntl(self, fd: int, cmd: int, arg: t.Union[bytes, int]=0) -> t.Union[bytes, int]:
        "This follows the same protocol as fcntl.fcntl."
        logger.debug("fcntl(%d, %d, %s)", fd, cmd, arg)
        return fcntl.fcntl(fd, cmd, arg)

class FDNamespace:
    pass

class MemoryNamespace:
    pass

class Task:
    def __init__(self, syscall: SyscallInterface, files: FDNamespace, memory: MemoryNamespace) -> None:
        self.syscall = syscall
        self.memory = memory
        self.files = files

class ProcessContext:
    """A Linux process with associated resources.

    Resources chiefly include memory and file descriptors. Maybe other
    things at some point.

    Eventually, when we support pipelining file descriptor creation, we'll need some
    kind of transactional interface, or a list of "pending" fds.

    This also contains a fixed SyscallInterface that is used to access this process.
    """
    def __init__(self, syscall_interface: SyscallInterface) -> None:
        self.syscall = syscall_interface

T = t.TypeVar('T')
class FileObject:
    """This is the underlying file object referred to by a file descriptor.

    Often, multiple file descriptors in multiple processes can refer
    to the same file object. For example, the stdin/stdout/stderr file
    descriptors will typically all refer to the same file object
    across several processes started by the same shell.

    This is unfortunate, because there are some useful mutations (in
    particular, setting O_NONBLOCK) which we'd like to perform to
    FileObjects, but which might break other users.

    We store whether the FileObject is shared with others with
    "shared". If it is, we can't mutate it.

    """
    shared: bool
    def __init__(self, shared: bool=False, flags: int=None) -> None:
        self.shared = shared

    async def set_nonblock(self, fd: 'FileDescriptor[FileObject]') -> None:
        if self.shared:
            raise Exception("file object is shared and can't be mutated")
        await fd.syscall.fcntl(fd.number, fcntl.F_SETFL, os.O_NONBLOCK)

T_file = t.TypeVar('T_file', bound=FileObject)
T_file_co = t.TypeVar('T_file_co', bound=FileObject, covariant=True)

class ReadableFileObject(FileObject):
    async def read(self, fd: 'FileDescriptor[ReadableFileObject]', count: int=4096) -> bytes:
        return (await fd.syscall.read(fd.number, count))
ReadableFile = ReadableFileObject

class WritableFileObject(FileObject):
    async def write(self, fd: 'FileDescriptor[WritableFileObject]', buf: bytes) -> int:
        return (await fd.syscall.write(fd.number, buf))
WritableFile = WritableFileObject

class FileDescriptor(t.Generic[T_file_co]):
    "A file descriptor."
    file: T_file_co
    task: Task
    fd_namespace: FDNamespace
    number: int
    def __init__(self, file: T_file_co, task: Task, fd_namespace: FDNamespace, number: int) -> None:
        self.file = file
        self.task = task
        self.fd_namespace = fd_namespace
        self.number = number
        self.open = True

    @property
    def syscall(self) -> SyscallInterface:
        if self.task.files != self.fd_namespace:
            raise Exception("Can't call syscalls on FD when my Task has moved out of my FDNamespaces")
        return self.task.syscall

    async def aclose(self):
        if self.open:
            await self.syscall.close(self.number)
            self.open = False
        else:
            pass

    async def __aenter__(self) -> 'FileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    def release(self) -> 'FileDescriptor[T_file_co]':
        """Disassociate the file descriptor from this object

        """
        if self.open:
            self.open = False
            return self.__class__(self.file, self.task, self.fd_namespace, self.number)
        else:
            raise Exception("file descriptor already closed")

    async def dup2(self, target: 'FileDescriptor') -> 'FileDescriptor[T_file_co]':
        """Make a copy of this file descriptor at target.number

        """
        if self.fd_namespace != target.fd_namespace:
            raise Exception("two fds are not in the same FDNamespace")
        if self is target:
            return self
        owned_target: FileDescriptor = target.release()
        await self.syscall.dup2(self.number, owned_target.number)
        owned_target.open = False
        new_fd = type(self)(self.file, self.task, self.fd_namespace, owned_target.number)
        # dup2 unsets cloexec on the new copy, so:
        self.file.shared = True
        return new_fd

    async def enable_cloexec(self) -> None:
        self.file.shared = True
        raise NotImplementedError

    async def disable_cloexec(self) -> None:
        raise NotImplementedError

    # These are just helper methods which forward to the method on the underlying file object.
    async def set_nonblock(self: 'FileDescriptor[FileObject]') -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        await self.file.set_nonblock(self)

    async def read(self: 'FileDescriptor[ReadableFileObject]', count: int=4096) -> bytes:
        return (await self.file.read(self, count))

    async def write(self: 'FileDescriptor[WritableFileObject]', buf: bytes) -> int:
        return (await self.file.write(self, buf))

    async def add(self: 'FileDescriptor[EpollFileObject]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.add(self, fd, event)

    async def modify(self: 'FileDescriptor[EpollFileObject]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.modify(self, fd, event)

    async def delete(self: 'FileDescriptor[EpollFileObject]', fd: 'FileDescriptor') -> None:
        await self.file.delete(self, fd)

    async def wait(self: 'FileDescriptor[EpollFileObject]', maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await self.file.wait(self, maxevents, timeout))

    async def wait_readable(self) -> None:
        return (await self.syscall.wait_readable(self.number))

class EpollFileObject(FileObject):
    async def add(self, epfd: FileDescriptor['EpollFileObject'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_add(epfd.number, fd.number, event)

    async def modify(self, epfd: FileDescriptor['EpollFileObject'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_mod(epfd.number, fd.number, event)

    async def delete(self, epfd: FileDescriptor['EpollFileObject'], fd: FileDescriptor) -> None:
        await epfd.syscall.epoll_ctl_del(epfd.number, fd.number)

    async def wait(self, epfd: FileDescriptor['EpollFileObject'], maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await epfd.syscall.epoll_wait(epfd.number, maxevents, timeout))

async def allocate_epoll(task: Task) -> FileDescriptor[EpollFileObject]:
    epfd = await task.syscall.epoll_create(EPOLL_CLOEXEC)
    return FileDescriptor(EpollFileObject(), task, task.files, epfd)

class EpolledFileDescriptor(t.Generic[T_file_co]):
    epoller: 'Epoller'
    underlying: FileDescriptor[T_file_co]
    queue: trio.hazmat.UnboundedQueue
    def __init__(self, epoller: 'Epoller', underlying: FileDescriptor[T_file_co], queue: trio.hazmat.UnboundedQueue) -> None:
        self.epoller = epoller
        self.underlying = underlying
        self.queue = queue

    async def modify(self, events: EpollEventMask) -> None:
        await self.epoller.epfd.modify(self.underlying, EpollEvent(self.underlying.number, events))

    async def wait(self) -> t.List[EpollEvent]:
        while True:
            try:
                return self.queue.get_batch_nowait()
            except trio.WouldBlock:
                await self.epoller.do_wait()

    async def aclose(self) -> None:
        await self.epoller.epfd.delete(self.underlying)
        await self.underlying.aclose()

    async def __aenter__(self) -> 'EpolledFileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

class Epoller:
    def __init__(self, epfd: FileDescriptor[EpollFileObject]) -> None:
        self.epfd = epfd
        self.fd_map: t.Dict[int, EpolledFileDescriptor] = {}
        self.running_wait: t.Optional[trio.Event] = None

    async def add(self, fd: FileDescriptor[T_file], events: EpollEventMask=None) -> EpolledFileDescriptor:
        if events is None:
            events = EpollEventMask()
        queue = trio.hazmat.UnboundedQueue()
        wrapper = EpolledFileDescriptor(self, fd, queue)
        self.fd_map[fd.number] = wrapper
        await self.epfd.add(fd, EpollEvent(fd.number, events))
        return wrapper

    async def do_wait(self) -> None:
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait

            await self.epfd.wait_readable()
            received_events = await self.epfd.wait(maxevents=32, timeout=-1)
            for event in received_events:
                queue = self.fd_map[event.data].queue
                queue.put_nowait(event.events)

            self.running_wait = None
            running_wait.set()

    async def aclose(self) -> None:
        await self.epfd.aclose()

    async def __aenter__(self) -> 'Epoller':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()


class AsyncFileDescriptor(t.Generic[T_file_co]):
    epolled: EpolledFileDescriptor[T_file_co]

    @staticmethod
    async def make(epoller: Epoller, fd: FileDescriptor[T_file]) -> 'AsyncFileDescriptor[T_file]':
        await fd.set_nonblock()
        epolled = await epoller.add(fd, EpollEventMask.make(in_=True, out=True, et=True))
        return AsyncFileDescriptor(epolled)

    def __init__(self, epolled: EpolledFileDescriptor[T_file_co]) -> None:
        self.epolled = epolled
        self.running_wait: t.Optional[trio.Event] = None
        self.is_readable = False
        self.is_writable = False

    async def _wait_once(self):
        if self.running_wait is not None:
            await self.running_wait.wait()
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait

            events = await self.epolled.wait()
            for event in events:
                if event.in_: self.is_readable = True
                if event.out: self.is_writable = True
                # TODO the rest
            
            self.running_wait = None
            running_wait.set()

    async def read(self: 'AsyncFileDescriptor[ReadableFileObject]', count: int=4096) -> bytes:
        while True:
            try:
                return (await self.epolled.underlying.read())
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                    while not self.is_readable:
                        await self._wait_once()
                else:
                    raise

    async def write(self: 'AsyncFileDescriptor[WritableFileObject]', buf: bytes) -> None:
        while len(buf) > 0:
            try:
                written = await self.epolled.underlying.write(buf)
                buf = buf[written:]
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_writable = False
                    while not self.is_writable:
                        await self._wait_once()
                else:
                    raise

    async def aclose(self) -> None:
        await self.epolled.aclose()

    async def __aenter__(self) -> 'AsyncFileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

def create_current_task() -> Task:
    return Task(LocalSyscall(trio.hazmat.wait_readable),
                FDNamespace(), MemoryNamespace())

# TODO we should have a ProcessLaunchBootstrap which has these
# standard streams along with args/env and one task
class StandardStreams:
    stdin: FileDescriptor[ReadableFileObject]
    stdout: FileDescriptor[WritableFileObject]
    stderr: FileDescriptor[WritableFileObject]

    def __init__(self,
                 stdin: FileDescriptor[ReadableFileObject],
                 stdout: FileDescriptor[WritableFileObject],
                 stderr: FileDescriptor[WritableFileObject]) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

def wrap_stdin_out_err(task: Task) -> StandardStreams:
    stdin = FileDescriptor(ReadableFile(shared=True), task, task.files, 0)
    stdout = FileDescriptor(WritableFile(shared=True), task, task.files, 1)
    stderr = FileDescriptor(WritableFile(shared=True), task, task.files, 2)
    return StandardStreams(stdin, stdout, stderr)

class Pipe:
    def __init__(self, rfd: FileDescriptor[ReadableFile],
                 wfd: FileDescriptor[WritableFile]) -> None:
        self.rfd = rfd
        self.wfd = wfd

    async def aclose(self):
        await self.rfd.aclose()
        await self.wfd.aclose()

    async def __aenter__(self) -> 'Pipe':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

async def allocate_pipe(task: Task) -> Pipe:
    r, w = await task.syscall.pipe()
    return Pipe(FileDescriptor(ReadableFile(shared=False), task, task.files, r),
                FileDescriptor(WritableFile(shared=False), task, task.files, w))

class SubprocessContext:
    def __init__(self, task: Task, child_files: FDNamespace, parent_files: FDNamespace) -> None:
        self.task = task
        self.child_files = child_files
        self.parent_files = parent_files
        self.pid: t.Optional[int] = None

    def translate(self, fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
        """Translate FDs from the parent's FilesNS to the child's FilesNS

        Any file descriptor created by my task in parent_files is now
        also present in child_files, so we're able to translate them
        to child_files.

        This only works for fds created by my task because fds from
        other tasks may have been created after the fork, through
        concurrent execution. To translate fds from other tasks,
        provide them as arguments at fork time.

        """
        if self.pid is not None:
            raise Exception("Already left the subprocess")
        if fd.fd_namespace != self.parent_files:
            raise Exception("Can't translate an fd not coming from my parent's FDNamespace")
        if fd.task != self.task:
            raise Exception("Can't translate an fd not coming from my Task; it could have been created after the fork.")
        return type(fd)(fd.file, fd.task, self.child_files, fd.number)

    @property
    def syscall(self) -> SyscallInterface:
        if self.pid is not None:
            raise Exception("Already left this process")
        return self.task.syscall

    async def exit(self, status: int) -> None:
        self.pid = await self.syscall.exit(status)
        self.task.files = self.parent_files

    async def exec(self, pathname: os.PathLike, argv: t.List[t.Union[str, bytes]],
             *, envp: t.Optional[t.Dict[str, str]]=None) -> None:
        if envp is None:
            envp = dict(**os.environ)
        self.pid = await self.syscall.execveat(sfork.AT_FDCWD,
                                               sfork.to_bytes(os.fspath(pathname)), [sfork.to_bytes(arg) for arg in argv],
                                               sfork.serialize_environ(**envp), flags=0)
        self.task.files = self.parent_files

@asynccontextmanager
async def subprocess(task: Task) -> t.Any:
    # the way we are setting a variable to a new thing, then resetting
    # it back to an old thing, is really contextvar-ish. but it's
    # inside an explicitly passed around object. but it's still the
    # same kind of behavior. by what name is this known?

    parent_files = task.files
    await task.syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
    child_files = FDNamespace()
    task.files = child_files
    context = SubprocessContext(task, child_files, parent_files)
    try:
        yield context
    finally:
        if context.pid is None:
            await context.exit(0)

class Process:
    def __init__(self, killfd: FileDescriptor[WritableFile],
                 waitfd: FileDescriptor[ReadableFile]) -> None:
        self.killfd = killfd
        self.waitfd = waitfd

    async def check(self) -> None:
        pass


@asynccontextmanager
async def clonefd(task: Task) -> t.Any:
    supervise = 
    async with subprocess(task) as supervise_proc:
        async with subprocess(task) as user_proc:
            yield user_proc
