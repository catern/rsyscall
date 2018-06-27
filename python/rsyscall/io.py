from rsyscall._raw import ffi, lib # type: ignore
import abc
import os
import typing as t
import trio
import signal
import sfork
from async_generator import asynccontextmanager

class ProcessContext:
    """A Linux process with associated resources.

    Resources chiefly include memory and file descriptors. Maybe other
    things at some point.

    Eventually, when we support pipelining file descriptor creation, we'll need some
    kind of transactional interface, or a list of "pending" fds.
    """
    pass

local_process = ProcessContext()

class SyscallInterface:
    process: ProcessContext
    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int: ...
    async def pipe(self, flags=os.O_NONBLOCK) -> t.Tuple[int, int]: ...
    async def close(self, fd: int) -> None: ...
    # TODO add optional offset argument?
    # TODO figure out how to allow preadv2 flags?
    async def read(self, fd: int, count: int) -> bytes: ...
    async def write(self, fd: int, buf: bytes) -> int: ...
    async def wait_readable(self, fd: int) -> None: ...
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int: ...
    async def exit(self, status: int) -> int: ...
    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> int: ...

def _to_char_star_array(args: t.List[bytes]) -> t.Any:
    argv = ffi.new('char *const[]', len(args) + 1)
    for i, arg in enumerate(args):
        argv[i] = ffi.from_buffer(arg)
    return argv

class LocalSyscall(SyscallInterface):
    def __init__(self, wait_readable) -> None:
        self.process = local_process
        self._wait_readable = wait_readable

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        print("before", number, arg1, arg2, arg3, arg4, arg5, arg6)
        val = lib.my_syscall(number, arg1, arg2, arg3, arg4, arg5)
        print("returning", val)
        print("after", number, arg1, arg2, arg3, arg4, arg5, arg6)
        if (val == -1):
            err = ffi.errno
            raise OSError(err, os.strerror(err))
        return val

    async def pipe(self, flags=os.O_NONBLOCK) -> t.Tuple[int, int]:
        print("pipe", flags)
        return os.pipe2(flags)

    async def close(self, fd: int) -> None:
        print("close", fd)
        return os.close(fd)

    # TODO allow setting offset?
    async def read(self, fd: int, count: int) -> bytes:
        print("read", fd, count)
        return os.read(fd, count)

    async def write(self, fd: int, buf: bytes) -> int:
        print("write", fd, buf)
        return os.write(fd, buf)

    # TODO support setting child_stack so we can create threads
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int:
        print("clone", deathsig)
        if deathsig is not None:
            flags |= deathsig
        return sfork.clone(flags)

    async def exit(self, status: int) -> int:
        print("exit", status)
        return sfork.exit(status)

    async def execveat(self, pathname: bytes, argv: t.List[bytes], envp: t.List[bytes], flags: int,
                       *, dirfd: t.Optional[int]=None) -> int:
        print("execveat", pathname)
        return sfork.execveat(pathname, argv, envp, flags, dirfd=dirfd)

class FileDescriptor(trio.abc.AsyncResource):
    "A file descriptor."
    def __init__(self, syscall: SyscallInterface, number: int) -> None:
        self.syscall = syscall
        self.number = number

    async def aclose(self):
        await self.syscall.close(self.number)

class ReadableFileDescriptor(FileDescriptor):
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

async def allocate_pipe(syscall: SyscallInterface) -> Pipe:
    r, w = await syscall.pipe()
    return Pipe(ReadableFileDescriptor(syscall, r), WritableFileDescriptor(syscall, w))

class SubprocessContext:
    def __init__(self, syscall: SyscallInterface, process: ProcessContext, parent_process: ProcessContext) -> None:
        self.syscall = syscall
        self.process = process
        self.parent_process = parent_process
        self.pid: t.Optional[int] = None

    def _can_syscall(self) -> None:
        if self.syscall.process is not self.process:
            raise Exception("My syscall interface is not currently operating on my process, "
                            "did you fork again and call exit/exec out of order?")
        if self.pid is not None:
            raise Exception("Already left this process")

    async def exit(self, status: int) -> None:
        self._can_syscall()
        self.pid = await self.syscall.exit(status)
        self.syscall.process = self.parent_process

    async def exec(self, pathname: os.PathLike, argv: t.List[t.Union[str, bytes]],
             *, envp: t.Optional[t.Dict[str, str]]=None) -> None:
        self._can_syscall()
        if envp is None:
            envp = os.environ
        self.pid = await self.syscall.execveat(to_bytes(os.fspath(pathname)), [to_bytes(arg) for arg in argv],
                                               serialize_environ(**envp), flags=0)
        self.syscall.process = self.parent_process

@asynccontextmanager
async def subprocess(syscall: SyscallInterface) -> t.Any:
    # this is really contextvar-ish. but I guess it's inside an
    # explicitly passed around object in the rsyscall case. but it's
    # still the same kind of behavior. by what name is this known?
    parent_process = syscall.process
    await syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
    current_process = ProcessContext()
    syscall.process = current_process
    context = SubprocessContext(syscall, current_process, parent_process)
    try:
        yield context
    finally:
        if context.pid is None:
            await context.exit(0)
