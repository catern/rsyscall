from rsyscall._raw import ffi, lib # type: ignore
import abc
import os
import typing as t
import trio
import signal
import sfork
from async_generator import asynccontextmanager
import logging
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
        return os.dup2(oldfd, newfd)

    # TODO support setting child_stack so we can create threads
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int:
        logger.debug("clone(%d, %s)", flags, deathsig)
        if deathsig is not None:
            flags |= deathsig
        return sfork.clone(flags)

    async def exit(self, status: int) -> int:
        logger.debug("exit(%d)", status)
        return sfork.exit(status)

    async def execveat(self, pathname: bytes, argv: t.List[bytes], envp: t.List[bytes], flags: int,
                       *, dirfd: t.Optional[int]=None) -> int:
        logger.debug("execveat(%s)", pathname)
        return sfork.execveat(pathname, argv, envp, flags, dirfd=dirfd)

class FilesNamespace:
    pass

class MemoryNamespace:
    pass

class Task:
    def __init__(self, syscall: SyscallInterface, files: FilesNamespace, memory: MemoryNamespace) -> None:
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

class FileDescriptor(trio.abc.AsyncResource):
    "A file descriptor."
    def __init__(self, task: Task, files: FilesNamespace, number: int) -> None:
        self.task = task
        self.files = files
        self.number = number
        self.open = True

    @property
    def syscall(self) -> SyscallInterface:
        if self.task.files != self.files:
            raise Exception("Can't call syscalls on FD when my Task has moved out of my FilesNamespaces")
        return self.task.syscall

    async def dup2(self, target: 'FileDescriptor') -> 'FileDescriptor':
        """Make a copy of this file descriptor at target.number

        TODO: The type annotation should represent that this returns
        the same type as self.

        """
        if self.files != target.files:
            raise Exception("two fds are not in the same FilesNamespace")
        if self is target:
            return self
        owned_target = target.release()
        await self.syscall.dup2(self.number, owned_target.number)
        owned_target.open = False
        return type(self)(self.task, self.files, owned_target.number)

    def release(self) -> 'FileDescriptor':
        """Disassociate the file descriptor from this object

        TODO: The type annotation should represent that this returns
        the same type as self.

        """
        if self.open:
            self.open = False
            return type(self)(self.task, self.files, self.number)
        else:
            raise Exception("file descriptor already closed")

    async def aclose(self):
        if self.open:
            await self.syscall.close(self.number)
            self.open = False
        else:
            raise Exception("file descriptor already closed")

class ReadableFileDescriptor(FileDescriptor):
    # TODO we need to send this read through an epoll thingy.
    # that's a shared resource, hum hom herm
    async def read(self, count: int=4096) -> bytes:
        return (await self.syscall.read(self.number, count))

class WritableFileDescriptor(FileDescriptor):
    async def write(self, buf: bytes) -> int:
        return (await self.syscall.write(self.number, buf))

class Pipe(trio.abc.AsyncResource):
    def __init__(self, rfd: ReadableFileDescriptor, wfd: WritableFileDescriptor) -> None:
        self.rfd = rfd
        self.wfd = wfd

    async def aclose(self):
        await self.rfd.aclose()
        await self.wfd.aclose()

async def allocate_pipe(task: Task) -> Pipe:
    r, w = await task.syscall.pipe()
    return Pipe(ReadableFileDescriptor(task, task.files, r), WritableFileDescriptor(task, task.files, w))

class EpollEvent:
    # should improve the accuracy of these.
    events: int
    data: int

class EpollFileDescriptor(FileDescriptor):
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
class EpollRegisteredFD(trio.AsyncResource):
    epoller: 'Epoller'
    underlying: FileDescriptor
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

class Epoller:
    def convert(self, fd: FileDescriptor) -> EpollRegisteredFD:
        pass

class SubprocessContext:
    def __init__(self, task: Task, child_files: FilesNamespace, parent_files: FilesNamespace) -> None:
        self.task = task
        self.child_files = child_files
        self.parent_files = parent_files
        self.pid: t.Optional[int] = None

    def translate(self, fd: FileDescriptor) -> FileDescriptor:
        """Translate FDs from the parent's FilesNS to the child's FilesNS

        Any file descriptor created by my task in parent_files is now
        also present in child_files, so we're able to translate them
        to child_files.

        This only works for fds created by my task because fds from
        other tasks may have been created after the fork, through
        concurrent execution. To translate fds from other tasks,
        provide them as arguments at fork time.

        TODO: The type should take any class inheriting from FD, and
        return the same class. Not sure how to represent that in mypy.

        """
        if self.pid is not None:
            raise Exception("Already left the subprocess")
        if fd.files != self.parent_files:
            raise Exception("Can't translate an fd not coming from my parent's FilesNamespace")
        if fd.task != self.task:
            raise Exception("Can't translate an fd not coming from my Task; it could have been created after the fork.")
        return type(fd)(fd.task, self.child_files, fd.number)

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
            envp = os.environ
        self.pid = await self.syscall.execveat(sfork.to_bytes(os.fspath(pathname)), [sfork.to_bytes(arg) for arg in argv],
                                               sfork.serialize_environ(**envp), flags=0)
        self.task.files = self.parent_files

@asynccontextmanager
async def subprocess(task: Task) -> t.Any:
    # this is really contextvar-ish. but I guess it's inside an
    # explicitly passed around object. but it's still the same kind of
    # behavior. by what name is this known?

    parent_files = task.files
    await task.syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
    child_files = FilesNamespace()
    task.files = child_files
    context = SubprocessContext(task, child_files, parent_files)
    try:
        yield context
    finally:
        if context.pid is None:
            await context.exit(0)
        
