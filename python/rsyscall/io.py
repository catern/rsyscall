from rsyscall._raw import ffi, lib # type: ignore
import abc
import os
import typing as t
import trio
import signal
import sfork
from async_generator import asynccontextmanager
import logging
import fcntl
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

    """
    pass

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

T_fd = t.TypeVar('T_fd', bound='FileDescriptor')
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
            raise Exception("file descriptor already closed")

    async def __aenter__(self: T_fd) -> T_fd:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    def release(self: T_fd) -> T_fd:
        """Disassociate the file descriptor from this object

        """
        if self.open:
            self.open = False
            return self.__class__(self.file, self.task, self.fd_namespace, self.number) 
        else:
            raise Exception("file descriptor already closed")

    # These are just helper methods which forward to the method on the underlying file object.
    async def read(self: 'FileDescriptor[ReadableFileObject]', count: int=4096) -> bytes:
        return (await self.file.read(self, count))

    async def write(self: 'FileDescriptor[WritableFileObject]', buf: bytes) -> int:
        return (await self.file.write(self, buf))

class SharedFileDescriptor(FileDescriptor[T_file_co]):
    "A file descriptor, referencing some file object that is also referenced by other FDs and processes."
    async def dup2(self: 'SharedFileDescriptor[T_file]', target: 'FileDescriptor') -> 'SharedFileDescriptor[T_file]':
        """Make a copy of this file descriptor at target.number

        """
        if self.fd_namespace != target.fd_namespace:
            raise Exception("two fds are not in the same FDNamespace")
        if self is target:
            return self
        owned_target = target.release()
        await self.syscall.dup2(self.number, owned_target.number)
        owned_target.open = False
        return type(self)(self.file, self.task, self.fd_namespace, owned_target.number)

    async def enable_cloexec(self) -> None:
        raise NotImplementedError

    async def disable_cloexec(self) -> None:
        raise NotImplementedError
SharedFD = SharedFileDescriptor

class UniqueFileDescriptor(FileDescriptor[T_file_co]):
    """A file descriptor, uniquely referencing some specific file object.

    In other words, only our program has this file object, I guess. It
    doesn't necessarily mean that there's only one file descriptor
    pointing to that file object.

    All such FDs should have CLOEXEC set.

    """
    async def set_nonblock(self) -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        # TODO first I need to have the file flags stored...
        raise NotImplementedError

    async def convert_to_shared(self) -> SharedFileDescriptor[T_file_co]:
        ret = SharedFileDescriptor(self.file, self.task, self.fd_namespace, self.number)
        self.open = False
        return ret

UniqueFD = UniqueFileDescriptor

def create_current_task() -> Task:
    return Task(LocalSyscall(trio.hazmat.wait_readable),
                FDNamespace(), MemoryNamespace())

# TODO we should have a ProcessLaunchBootstrap which has these standard streams along with args/env and one task
class StandardStreams:
    stdin: SharedFileDescriptor[ReadableFileObject]
    stdout: SharedFileDescriptor[WritableFileObject]
    stderr: SharedFileDescriptor[WritableFileObject]

    def __init__(self,
                 stdin: SharedFileDescriptor[ReadableFileObject],
                 stdout: SharedFileDescriptor[WritableFileObject],
                 stderr: SharedFileDescriptor[WritableFileObject]) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

def wrap_stdin_out_err(task: Task) -> StandardStreams:
    stdin = SharedFD(ReadableFile(), task, task.files, 0)
    stdout = SharedFD(WritableFile(), task, task.files, 1)
    stderr = SharedFD(WritableFile(), task, task.files, 2)
    return StandardStreams(stdin, stdout, stderr)

class Pipe:
    def __init__(self, rfd: UniqueFD[ReadableFile],
                 wfd: UniqueFD[WritableFile]) -> None:
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
    return Pipe(UniqueFD(ReadableFile(), task, task.files, r),
                UniqueFD(WritableFile(), task, task.files, w))

class EpollEvent:
    # should improve the accuracy of these.
    events: int
    data: int

class EpollFileObject(FileObject):
    async def add(self, fd: FileDescriptor, event: EpollEvent) -> None:
        pass

    async def delete(self, fd: FileDescriptor) -> None:
        pass

    async def modify(self, fd: FileDescriptor, event: EpollEvent) -> None:
        pass

    async def wait(self, maxevents: int=10) -> t.List[EpollEvent]:
        pass

# oh! this should be a generic wrapper type around a FileDescriptor.
# that way we can still see the underlying type right.
# and... maybe it can have different specializations?
# depending on the underlying...
# with extra methods...
# no that's dumb...
# but we do want to be able to read right or whatever...
# oh! we'll have another function which takes the specialized version and calls on it!
# hmm, extra methods depending on the underlying type doesn't seem infinitely bad.
# since you can easily achieve it in standalone functions
# oh because how do we even dispatch on the type
# hm
# okay, standalone functions that take a specialization are fine then.
# oh, I guess they could be staticmethods. or even... real methods... urgh...
# so this is yet another question for mypy people:
# can I make self be required to be a specific specialization?
# in the meantime I will just use methods then
# aha it's all possible, thank you mypy stuff

# can I have an EpollableFD that I inherit from multiple of?
# what if.. the constructors don't match in their type?
# aaaa
# forget it, just use free functions!
# no okay don't use free functions, but be aware it's weird.
# or maybe I should just use free functions aaa
class EpollWrapper(trio.abc.AsyncResource, t.Generic[T_file_co]):
    """A class that encapsulates an O_NONBLOCK fd registered with epoll.

    Theoretically you might want to register with epoll and set
    O_NONBLOCK separately.  But that would mean you'd have to track
    them each with separate wrapper types, which would be too much
    overhead.

    """

    epoller: 'Epoller'
    underlying: UniqueFileDescriptor[T_file_co]
    def __init__(self, epoller: 'Epoller', fd: UniqueFileDescriptor[T_file_co]) -> None:
        self.epoller = epoller
        self.underlying = fd

    # wait no we are supposed to do the IO first, then wait if it fails
    # hmmm....
    # not sure where to put such a helper method
    async def wait_readable(self):
        pass

    async def wait_writable(self):
        pass

    async def aclose(self):
        await self.epoller.delete(self.underlying)
        await self.underlying.aclose()

    async def read(self: 'EpollWrapper[ReadableFileObject]', count: int=4096) -> bytes:
        # TODO
        while True:
            try:
                return (await self.underlying.read())
            except:
                # if EAGAIN, 
                await self.wait_readable()
 
class Epoller:
    async def wrap(self, fd: UniqueFileDescriptor[T_file]) -> EpollWrapper[T_file]:
        await fd.set_nonblock()
        return EpollWrapper(self, fd)

class SubprocessContext:
    def __init__(self, task: Task, child_files: FDNamespace, parent_files: FDNamespace) -> None:
        self.task = task
        self.child_files = child_files
        self.parent_files = parent_files
        self.pid: t.Optional[int] = None

    def translate(self, fd: SharedFileDescriptor[T_file]) -> SharedFileDescriptor[T_file]:
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
    # this is really contextvar-ish. but I guess it's inside an
    # explicitly passed around object. but it's still the same kind of
    # behavior. by what name is this known?

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
        
L
