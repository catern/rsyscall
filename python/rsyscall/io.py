from rsyscall._raw import ffi, lib # type: ignore
import abc
import os
import typing as t
import trio
import signal
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
        if deathsig is not None:
            flags |= deathsig
        return (await self.syscall(lib.SYS_clone, flags, 0, 0, 0, 0))

    async def exit(self, status: int) -> int:
        print("exit", status)
        return (await self.syscall(lib.SYS_exit, status))

    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> int:
        return (await self.syscall(lib.SYS_execveat, dirfd, ffi.buffer(path),
                                   _to_char_star_array(argv),
                                   _to_char_star_array(envp),
                                   flags))

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

@asynccontextmanager
async def allocate_pipe(syscall: SyscallInterface) -> t.Any:
    r, w = await syscall.pipe()
    rfd, wfd = ReadableFileDescriptor(syscall, r), WritableFileDescriptor(syscall, w)
    async with rfd, wfd:
        yield rfd, wfd

class SubprocessContext:
    def __init__(self, process: ProcessContext, syscall: SyscallInterface) -> None:
        self.process = process
        self.syscall = syscall
        self.left = False

    # so we need to make sure when we call exit or exec,
    # that we're the active pid/process for this SyscallInterface.
    # oh yeah, hmm, essentially when we vfork we point the syscallinterface at a new processcontext.
    # 
    def _get_syscall(self) -> SyscallInterface:
        if self.syscall.process is not self.process:
            raise Exception("My syscall interface is not currently operating on my process, "
                            "did you fork again and call exit/exec out of order?")
        return self.syscall

    async def exit(self, status: int, syscall) -> None:
        my_pid = await syscall.exit(status)
        self.left = True
        return None
        # the pid is useless now.
        # exit and exec should return a Subprocess. or something.
        # er, just exec, I guess

@asynccontextmanager
async def make_subprocess(syscall: SyscallInterface) -> t.Any:
    # saved for later
    parent_process = syscall.process
    await syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
    child_process = ProcessContext()
    # this syscall interface now operates on the child process
    syscall.process = child_process
    context = SubprocessContext(child_process, syscall)
    try:
        yield context
    finally:
        if not context.left:
            print("forcibly exiting process")
            await context.exit(0)
        # this syscall interface has left the child process and is now
        # back to operating on the parent
        syscall.process = parent_process
