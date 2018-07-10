from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.epoll import EpollEvent, EpollEventMask, EPOLL_CLOEXEC
import rsyscall.epoll
from rsyscall.stat import StatxResult
import rsyscall.stat
import supervise_api as supervise
import random
import string
import abc
import prctl
import abc
import sys
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

    # task manipulation
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int: ...
    async def exit(self, status: int) -> int: ...
    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> int: ...
    async def getpid(self) -> int: ...

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
    async def prctl_set_child_subreaper(self, flag: bool) -> None: ...

    # statx returns a fixed-sized buffer which we parse outside the SyscallInterface
    async def statx(self, dirfd: int, pathname: bytes, flags: int, mask: int) -> bytes: ...

    async def faccessat(self, dirfd: int, pathname: bytes, mode: int) -> None: ...

    async def chdir(self, path: bytes) -> None: ...
    async def fchdir(self, fd: int) -> None: ...

    async def mkdirat(self, dirfd: int, pathname: bytes, mode: int) -> None: ...
    async def openat(self, dirfd: int, pathname: bytes, flags: int, mode: int) -> int: ...

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
        logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
        return sfork.execveat(dirfd, path, argv, envp, flags)

    async def getpid(self) -> int:
        return os.getpid()

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
    # hah, no, we should have a File...
    async def fcntl(self, fd: int, cmd: int, arg: t.Union[bytes, int]=0) -> t.Union[bytes, int]:
        "This follows the same protocol as fcntl.fcntl."
        logger.debug("fcntl(%d, %d, %s)", fd, cmd, arg)
        return fcntl.fcntl(fd, cmd, arg)

    async def prctl_set_child_subreaper(self, flag: bool) -> None:
        logger.debug("prctl_set_child_subreaper(%s)", flag)
        prctl.set_child_subreaper(flag)

    async def faccessat(self, dirfd: int, pathname: bytes, mode: int) -> None:
        logger.debug("faccessat(%s, %s, %s)", dirfd, pathname, mode)
        rsyscall.stat.faccessat(dirfd, pathname, mode)

    async def chdir(self, path: bytes) -> None:
        logger.debug("chdir(%s)", path)
        os.chdir(path)

    async def fchdir(self, fd: int) -> None:
        logger.debug("fchdir(%s)", fd)
        os.fchdir(fd)

    async def mkdirat(self, dirfd: int, pathname: bytes, mode: int) -> None:
        logger.debug("mkdirat(%s, %s, %s)", dirfd, pathname, mode)
        os.mkdir(pathname, mode, dir_fd=dirfd)

    async def openat(self, dirfd: int, pathname: bytes, flags: int, mode: int) -> int:
        logger.debug("openat(%s, %s, %s, %s)", dirfd, pathname, flags, mode)
        return os.open(pathname, flags, mode=mode, dir_fd=dirfd)

class FDNamespace:
    pass

class MemoryNamespace:
    pass

class MountNamespace:
    pass

class Task:
    def __init__(self, syscall: SyscallInterface,
                 fd_namespace: FDNamespace,
                 memory: MemoryNamespace,
                 mount: MountNamespace,
    ) -> None:
        self.syscall = syscall
        self.memory = memory
        self.fd_namespace = fd_namespace
        self.mount = mount

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
class File:
    """This is the underlying file object referred to by a file descriptor.

    Often, multiple file descriptors in multiple processes can refer
    to the same file object. For example, the stdin/stdout/stderr file
    descriptors will typically all refer to the same file object
    across several processes started by the same shell.

    This is unfortunate, because there are some useful mutations (in
    particular, setting O_NONBLOCK) which we'd like to perform to
    Files, but which might break other users.

    We store whether the File is shared with others with
    "shared". If it is, we can't mutate it.

    """
    shared: bool
    def __init__(self, shared: bool=False, flags: int=None) -> None:
        self.shared = shared

    async def set_nonblock(self, fd: 'FileDescriptor[File]') -> None:
        if self.shared:
            raise Exception("file object is shared and can't be mutated")
        await fd.syscall.fcntl(fd.number, fcntl.F_SETFL, os.O_NONBLOCK)

T_file = t.TypeVar('T_file', bound=File)
T_file_co = t.TypeVar('T_file_co', bound=File, covariant=True)

class ReadableFile(File):
    async def read(self, fd: 'FileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        return (await fd.syscall.read(fd.number, count))

class WritableFile(File):
    async def write(self, fd: 'FileDescriptor[WritableFile]', buf: bytes) -> int:
        return (await fd.syscall.write(fd.number, buf))

class ReadableWritableFile(ReadableFile, WritableFile):
    pass

class DirectoryFile(File):
    # TODO we should support getdents here
    pass

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
        if self.task.fd_namespace != self.fd_namespace:
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
        await self.syscall.dup2(self.number, target.number)
        target.open = False
        new_fd = type(self)(self.file, self.task, self.fd_namespace, target.number)
        # dup2 unsets cloexec on the new copy, so:
        self.file.shared = True
        return new_fd

    async def enable_cloexec(self) -> None:
        self.file.shared = True
        raise NotImplementedError

    async def disable_cloexec(self) -> None:
        raise NotImplementedError

    # These are just helper methods which forward to the method on the underlying file object.
    async def set_nonblock(self: 'FileDescriptor[File]') -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        await self.file.set_nonblock(self)

    async def read(self: 'FileDescriptor[ReadableFile]', count: int=4096) -> bytes:
        return (await self.file.read(self, count))

    async def write(self: 'FileDescriptor[WritableFile]', buf: bytes) -> int:
        return (await self.file.write(self, buf))

    async def add(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.add(self, fd, event)

    async def modify(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.modify(self, fd, event)

    async def delete(self: 'FileDescriptor[EpollFile]', fd: 'FileDescriptor') -> None:
        await self.file.delete(self, fd)

    async def wait(self: 'FileDescriptor[EpollFile]', maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await self.file.wait(self, maxevents, timeout))

    async def wait_readable(self) -> None:
        return (await self.syscall.wait_readable(self.number))

class EpollFile(File):
    async def add(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_add(epfd.number, fd.number, event)

    async def modify(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_mod(epfd.number, fd.number, event)

    async def delete(self, epfd: FileDescriptor['EpollFile'], fd: FileDescriptor) -> None:
        await epfd.syscall.epoll_ctl_del(epfd.number, fd.number)

    async def wait(self, epfd: FileDescriptor['EpollFile'], maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await epfd.syscall.epoll_wait(epfd.number, maxevents, timeout))

async def allocate_epoll(task: Task) -> FileDescriptor[EpollFile]:
    epfd = await task.syscall.epoll_create(EPOLL_CLOEXEC)
    return FileDescriptor(EpollFile(), task, task.fd_namespace, epfd)

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
    def __init__(self, epfd: FileDescriptor[EpollFile]) -> None:
        self.epfd = epfd
        self.fd_map: t.Dict[int, EpolledFileDescriptor] = {}
        self.running_wait: t.Optional[trio.Event] = None

    async def add(self, fd: FileDescriptor[T_file], events: EpollEventMask=None
    ) -> EpolledFileDescriptor:
        if events is None:
            events = EpollEventMask.make()
        fd = fd.release()
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

    async def read(self: 'AsyncFileDescriptor[ReadableFile]', count: int=4096) -> bytes:
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

    async def write(self: 'AsyncFileDescriptor[WritableFile]', buf: bytes) -> None:
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


class PathBase:
    """These are possible bases for Paths.

    A path can be interpreted relative to three different things:
    - A directory file descriptor
    - The task's root directory
    - The task's current working directory

    The latter two can change location, both by chdir and chroot, and
    by changing mount namespace.

    """
    @abc.abstractproperty
    def dirfd_num(self) -> int: ...
    @abc.abstractproperty
    def path_prefix(self) -> bytes: ...
    task: Task

class DirfdPathBase(PathBase):
    dirfd: FileDescriptor
    def __init__(self, dirfd: FileDescriptor) -> None:
        self.dirfd = dirfd
    @property
    def dirfd_num(self) -> int:
        return self.dirfd.number
    @property
    def path_prefix(self) -> bytes:
        return b""
    @property
    def task(self) -> Task:
        if self.dirfd.task.fd_namespace != self.dirfd.fd_namespace:
            raise Exception("Can't call syscalls on dirfd when my Task has moved out of my FDNamespaces")
        return self.dirfd.task

    def __str__(self) -> str:
        return f"Dirfd({self.dirfd.number})"

class RootPathBase(PathBase):
    task: Task
    def __init__(self, task: Task) -> None:
        self.task = task
    @property
    def dirfd_num(self) -> int:
        return sfork.AT_FDCWD
    @property
    def path_prefix(self) -> bytes:
        return b"/"
    def __str__(self) -> str:
        return "[ROOT]"

class CurrentWorkingDirectoryPathBase(PathBase):
    task: Task
    def __init__(self, task: Task) -> None:
        self.task = task
    @property
    def dirfd_num(self) -> int:
        return sfork.AT_FDCWD
    @property
    def path_prefix(self) -> bytes:
        return b""
    def __str__(self) -> str:
        return "[CWD]"

class Path:
    "This is our entry point to any syscall that takes a path argument."
    base: PathBase
    path: bytes
    def __init__(self, base: PathBase, path: t.Union[str, bytes]) -> None:
        self.base = base
        self.path = sfork.to_bytes(path)

    @staticmethod
    def from_bytes(task: Task, path: bytes) -> 'Path':
        if path.startswith(b"/"):
            return Path(RootPathBase(task), path[1:])
        else:
            return Path(CurrentWorkingDirectoryPathBase(task), path)

    @property
    def _full_path(self) -> bytes:
        return self.base.path_prefix + self.path

    @property
    def syscall(self) -> SyscallInterface:
        return self.base.task.syscall

    async def mkdir(self, mode=0o777) -> 'Path':
        await self.syscall.mkdirat(self.base.dirfd_num, self._full_path, mode)
        return self

    async def execve(self, argv: t.List[t.Union[str, bytes]], envp: t.Mapping[str, t.Union[str, bytes]]) -> int:
        # let's not worry too much about what execveat actually does in an sfork situation vs not sfork...
        # in sfork: starts new thread in current namespaces, returns current thread to stashed namespaces
        # out of sfork: starts new thread in current namespaces, destroys current thread
        ret = await self.syscall.execveat(
            self.base.dirfd_num, self._full_path,
            [sfork.to_bytes(arg) for arg in argv],
            sfork.serialize_environ(**envp), flags=0)
        return ret

    async def chdir(self) -> None:
        "Mutate the underlying task under this Path, changing its CWD to something new."
        if isinstance(self.base, DirfdPathBase):
            await self.syscall.fchdir(self.base.dirfd.number)
            await self.syscall.chdir(self.path)
        else:
            await self.syscall.chdir(self._full_path)

    async def open(self, flags: int, mode=0o644) -> FileDescriptor:
        """Open a path

        Note that this can block forever if we're opening a FIFO

        """
        if flags & os.O_WRONLY:
            file = WritableFile()
        elif flags & os.O_RDWR:
            file = ReadableWritableFile()
        elif flags & os.O_DIRECTORY:
            file = DirectoryFile()
        elif flags & os.O_PATH:
            file = File()
        else:
            # os.O_RDONLY is 0, so if we don't have any of the rest, then...
            file = ReadableFile()
        # hmm hmmm we need a task I guess, not just a syscall
        # so we can find the files
        fd_namespace = self.base.task.fd_namespace
        fd = await self.syscall.openat(self.base.dirfd_num, self._full_path, flags, mode)
        return FileDescriptor(file, self.base.task, fd_namespace, fd)

    async def creat(self, mode=0o644) -> FileDescriptor[WritableFile]:
        file = WritableFile()
        fd_namespace = self.base.task.fd_namespace
        fd = await self.syscall.openat(self.base.dirfd_num, self._full_path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, mode)
        return FileDescriptor(file, self.base.task, fd_namespace, fd)

    async def access(self, *, read=False, write=False, execute=False) -> bool:
        mode = 0
        if read:
            mode |= os.R_OK
        if write:
            mode |= os.W_OK
        if execute:
            mode |= os.X_OK
        # default to os.F_OK
        if mode == 0:
            mode = os.F_OK
        try:
            await self.syscall.faccessat(self.base.dirfd_num, self._full_path, mode)
            return True
        except OSError:
            return False

    def __truediv__(self, path_element: t.Union[str, bytes]) -> 'Path':
        element: bytes = sfork.to_bytes(path_element)
        if b"/" in element:
            raise Exception("no / allowed in path elements, do it one by one")
        return Path(self.base, self.path + b"/" + element)

    def __str__(self) -> str:
        return f"Path({self.base}, {self.path})"

class StandardStreams:
    stdin: FileDescriptor[ReadableFile]
    stdout: FileDescriptor[WritableFile]
    stderr: FileDescriptor[WritableFile]

    def __init__(self,
                 stdin: FileDescriptor[ReadableFile],
                 stdout: FileDescriptor[WritableFile],
                 stderr: FileDescriptor[WritableFile]) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

class UnixBootstrap:
    """The resources traditionally given to a process on startup in Unix.

    These are not absolutely guaranteed; environ and stdstreams are
    both userspace conventions. Still, we will rely on this for our
    tasks.

    """
    task: Task
    argv: t.List[bytes]
    environ: t.Mapping[bytes, bytes]
    stdstreams: StandardStreams
    def __init__(self,
                 task: Task,
                 argv: t.List[bytes],
                 environ: t.Mapping[bytes, bytes],
                 stdstreams: StandardStreams) -> None:
        self.task = task
        self.argv = argv
        self.environ = environ
        self.stdstreams = stdstreams

def wrap_stdin_out_err(task: Task) -> StandardStreams:
    stdin = FileDescriptor(ReadableFile(shared=True), task, task.fd_namespace, 0)
    stdout = FileDescriptor(WritableFile(shared=True), task, task.fd_namespace, 1)
    stderr = FileDescriptor(WritableFile(shared=True), task, task.fd_namespace, 2)
    return StandardStreams(stdin, stdout, stderr)

def gather_local_bootstrap() -> UnixBootstrap:
    task = Task(LocalSyscall(trio.hazmat.wait_readable),
                FDNamespace(), MemoryNamespace(), MountNamespace())
    argv = [arg.encode() for arg in sys.argv]
    environ = {key.encode(): value.encode() for key, value in os.environ.items()}
    stdstreams = wrap_stdin_out_err(task)
    return UnixBootstrap(task, argv, environ, stdstreams)


class ExecutableLookupCache:
    "Find executables by name, with a cache for the lookups"
    def __init__(self, paths: t.List[Path]) -> None:
        # we don't enforce that the paths are in the same mount
        # namespace or even the same host. that might lead to some
        # interesting/weird functionality.
        # execveat(fd) might be helpful here.
        self.paths = paths
        self.cache: t.Dict[bytes, Path] = {}

    async def uncached_lookup(self, name: bytes) -> t.Optional[Path]:
        if b"/" in name:
            raise Exception("name should be a single path element without any / present")
        for path in self.paths:
            filename = path/name
            if (await filename.access(read=True, execute=True)):
                return filename
        return None

    async def lookup(self, name: t.Union[str, bytes]) -> Path:
        basename: bytes = sfork.to_bytes(name)
        if basename in self.cache:
            return self.cache[basename]
        else:
            result = await self.uncached_lookup(basename)
            if result is None:
                raise Exception(f"couldn't find {name}")
            # we don't cache negative lookups
            self.cache[basename] = result
            return result

class UnixUtilities:
    rm: Path
    def __init__(self, rm: Path) -> None:
        self.rm = rm

async def build_unix_utilities(exec_cache: ExecutableLookupCache) -> UnixUtilities:
    rm = await exec_cache.lookup("rm")
    return UnixUtilities(rm=rm)

class UnixEnvironment:
    """The utilities provided by a standard Unix userspace.

    These are primarily built from various environment variables.

    """
    # various things picked up by environment variables
    executable_lookup_cache: ExecutableLookupCache
    tmpdir: Path
    # utilities are eagerly looked up in PATH
    utilities: UnixUtilities
    # locale?
    # home directory?
    def __init__(self,
                 executable_lookup_cache: ExecutableLookupCache,
                 tmpdir: Path,
                 utilities: UnixUtilities,
    ) -> None:
        self.executable_lookup_cache = executable_lookup_cache
        self.tmpdir = tmpdir
        self.utilities = utilities

async def build_unix_environment(bootstrap: UnixBootstrap) -> UnixEnvironment:
    executable_dirs: t.List[Path] = []
    for prefix in bootstrap.environ[b"PATH"].split(b":"):
        executable_dirs.append(Path.from_bytes(bootstrap.task, prefix))
    executable_lookup_cache = ExecutableLookupCache(executable_dirs)
    tmpdir = Path.from_bytes(bootstrap.task, bootstrap.environ[b"TMPDIR"])
    utilities = await build_unix_utilities(executable_lookup_cache)
    return UnixEnvironment(
        executable_lookup_cache=executable_lookup_cache,
        tmpdir=tmpdir,
        utilities=utilities,
    )

async def spit(path: Path, text: t.Union[str, bytes]) -> Path:
    """Open a file, creating and truncating it, and write the passed text to it

    Probably shouldn't use this on FIFOs or anything.

    Returns the passed-in Path so this serves as a nice pseudo-constructor.

    """
    data = sfork.to_bytes(text)
    async with (await path.creat()) as fd:
        while len(data) > 0:
            ret = await fd.write(data)
            data = data[ret:]
    return path

@asynccontextmanager
async def mkdtemp(root: Path, rm_location: Path, prefix: str="mkdtemp") -> t.AsyncGenerator[Path, None]:
    random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    basename = prefix+"."+random_suffix
    path = root/basename
    await path.mkdir(mode=0o700)
    async with (await path.open(os.O_DIRECTORY|os.O_PATH)) as dirfd:
        yield Path(DirfdPathBase(dirfd), b".")
        async with subprocess(root.base.task) as rm_proc:
            await root.chdir()
            await rm_proc.exec(rm_location, ["rm", "-r", basename])

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
    return Pipe(FileDescriptor(ReadableFile(shared=False), task, task.fd_namespace, r),
                FileDescriptor(WritableFile(shared=False), task, task.fd_namespace, w))

class SubprocessContext:
    def __init__(self, task: Task, child_files: FDNamespace, parent_files: FDNamespace) -> None:
        self.task = task
        self.child_files = child_files
        self.parent_files = parent_files
        self.pid: t.Optional[int] = None

    def translate(self, fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
        """Translate FDs from the parent's FDNamespace to the child's FDNamespace

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
        self.task.fd_namespace = self.parent_files

    async def exec(self, path: Path, argv: t.List[t.Union[str, bytes]],
             *, envp: t.Optional[t.Mapping[str, str]]=None) -> None:
        if envp is None:
            # TODO os.environ should actually be pulled from, er... somewhere
            envp = dict(**os.environ)
        # this is too restrictive but whatever
        if path.base.task != self.task:
            raise Exception("can't exec a path from another task")
        self.pid = await path.execve(argv, envp)
        self.task.fd_namespace = self.parent_files

    async def fexec(self, fd: FileDescriptor, argv: t.List[t.Union[str, bytes]],
                    *, envp: t.Optional[t.Dict[str, str]]=None) -> None:
        if envp is None:
            envp = dict(**os.environ)
        # TODO this won't work for scripts since cloexec needs to be unset
        self.pid = await self.syscall.execveat(
            fd.number, b"",
            [sfork.to_bytes(arg) for arg in argv],
            sfork.serialize_environ(**envp), flags=rsyscall.epoll.AT_EMPTY_PATH)
        self.task.fd_namespace = self.parent_files

@asynccontextmanager
async def subprocess(task: Task) -> t.Any:
    # the way we are setting a variable to a new thing, then resetting
    # it back to an old thing, is really contextvar-ish. but it's
    # inside an explicitly passed around object. but it's still the
    # same kind of behavior. by what name is this known?

    parent_files = task.fd_namespace
    await task.syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
    child_files = FDNamespace()
    task.fd_namespace = child_files
    context = SubprocessContext(task, child_files, parent_files)
    try:
        yield context
    finally:
        if context.pid is None:
            await context.exit(0)

class Process:
    """A single process addressed with a killfd and waitfd"""
    def __init__(self, killfd: AsyncFileDescriptor[WritableFile],
                 waitfd: AsyncFileDescriptor[ReadableFile],
                 pid: int) -> None:
        self.killfd = killfd
        self.waitfd = waitfd
        self.pid = pid
        self.child_event_buffer = supervise.ChildEventBuffer()

    async def close(self) -> None:
        await self.killfd.aclose()
        await self.waitfd.aclose()

    async def events(self) -> t.Any:
        while True:
            ret = await self.waitfd.read()
            if len(ret) == 0:
                # EOF
                return
            self.child_event_buffer.feed(ret)
            while True:
                event = self.child_event_buffer.consume()
                if event:
                    yield event
                else:
                    break

    async def check(self) -> None:
        async for event in self.events():
            if event.pid != self.pid:
                continue
            if event.died():
                return event.check()
        raise supervise.UncleanExit()

    async def send_signal(self, signum: signal.Signals):
        """Send this signal to the main child process."""
        if not isinstance(signum, int):
            raise TypeError("signum must be an integer: {}".format(signum))
        msg = supervise.ffi.new('struct supervise_send_signal*', {'pid':self.pid, 'signal':signum})
        buf = bytes(ffi.buffer(msg))
        await self.killfd.write(buf)

    async def terminate(self):
        """Terminate the main child process with SIGTERM.

        Note that this does not kill all descendent processes.
        For that, call close().
        """
        await self.send_signal(signal.SIGTERM)

    async def kill(self):
        """Kill the main child process with SIGKILL.

        Note that this does not kill all descendent processes.
        For that, call close().
        """
        await self.send_signal(signal.SIGKILL)

class RawProcess:
    def __init__(self, killfd: FileDescriptor[WritableFile],
                 waitfd: FileDescriptor[ReadableFile],
                 pid: int) -> None:
        self.killfd = killfd
        self.waitfd = waitfd
        self.pid = pid

    async def make_async(self, epoller: Epoller) -> Process:
        async_killfd = await AsyncFileDescriptor.make(epoller, self.killfd)
        async_waitfd = await AsyncFileDescriptor.make(epoller, self.waitfd)
        return Process(async_killfd, async_waitfd, self.pid)

class SupervisedSubprocessContext:
    def __init__(self, super_subproc: SubprocessContext, user_subproc: SubprocessContext) -> None:
        self.super_subproc = super_subproc
        self.user_subproc = user_subproc
        self.raw_proc: t.Optional[RawProcess] = None

    def translate(self, fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
        return self.super_subproc.translate(self.user_subproc.translate(fd))

    async def exit(self, status: int) -> None:
        await self.user_subproc.exit(status)

    async def exec(self, path: Path, argv: t.List[t.Union[str, bytes]],
                   *, envp: t.Optional[t.Dict[str, str]]=None) -> None:
        await self.user_subproc.exec(path, argv, envp=envp)

@asynccontextmanager
async def clonefd(task: Task, stdstreams: StandardStreams) -> t.Any:
    async with (await allocate_pipe(task)) as pipe_in:
        async with (await allocate_pipe(task)) as pipe_out:
            async with subprocess(task) as super_proc:
                os.setsid()
                prctl.set_child_subreaper(True)
                try:
                    async with subprocess(task) as user_proc:
                        supervised_subproc = SupervisedSubprocessContext(super_proc, user_proc)
                        yield supervised_subproc
                finally:
                    # we launch supervise regardless of whether an exception is thrown,
                    # to clean up child processes.
                    await super_proc.translate(pipe_in.rfd).dup2(
                        super_proc.translate(stdstreams.stdin))
                    await super_proc.translate(pipe_out.wfd).dup2(
                        super_proc.translate(stdstreams.stdout))
                    await super_proc.exec(supervise.supervise_utility_location, [], envp={})
            supervised_subproc.raw_proc = RawProcess(
                pipe_in.wfd.release(), pipe_out.rfd.release(), user_proc.pid)






