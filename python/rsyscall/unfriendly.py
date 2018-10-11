from rsyscall.base import Pointer, RsyscallException, RsyscallHangup
from rsyscall.base import T_addr, UnixAddress, PathTooLongError, InetAddress
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import os

class Task:
    pass

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
    def __init__(self, shared: bool=False) -> None:
        self.shared = shared

    async def set_nonblock(self, fd: FileDescriptor[File]) -> None:
        if self.shared:
            raise Exception("file object is shared and can't be mutated")
        if fd.file != self:
            raise Exception("can't set a file to nonblocking through a file descriptor that doesn't point to it")
        await raw_syscall.fcntl(fd.task.syscall, fd.pure, fcntl.F_SETFL, os.O_NONBLOCK)

T_file = t.TypeVar('T_file', bound=File)
T_file_co = t.TypeVar('T_file_co', bound=File, covariant=True)

class ReadableFile(File):
    async def read(self, fd: FileDescriptor[ReadableFile], buf: Pointer, count: int) -> int:
        return (await raw_syscall.read(fd.task.syscall, fd.pure, buf, count))

class WritableFile(File):
    async def write(self, fd: FileDescriptor[WritableFile], buf: Pointer, count: int) -> int:
        return (await raw_syscall.write(fd.task.syscall, fd.pure, buf, count))

class SeekableFile(File):
    async def lseek(self, fd: FileDescriptor[SeekableFile], offset: int, whence: int) -> int:
        return (await raw_syscall.lseek(fd.task.syscall, fd.pure, offset, whence))

class ReadableWritableFile(ReadableFile, WritableFile):
    pass

class SignalFile(ReadableFile):
    async def signalfd(self, fd: FileDescriptor[SignalFile], mask: Pointer, sizemask: int) -> None:
        await raw_syscall.signalfd4(fd.task.syscall, mask, sizemask, 0, fd=fd.pure)

class PathFile(File):
    # TODO should fill this place with delicious path operations
    pass

class DirectoryFile(SeekableFile, PathFile):
    async def getdents(self, fd: FileDescriptor[DirectoryFile], dirp: Pointer, count: int) -> int:
        return (await raw_syscall.getdents64(fd.task.syscall, fd.pure, dirp, count))

class EpollFile(File):
    async def add(self, epfd: FileDescriptor[EpollFile], fd: FileDescriptor, event: Pointer) -> None:
        await raw_syscall.epoll_ctl(epfd.task.syscall, epfd.pure, EpollCtlOp.ADD, fd.pure, event)

    async def modify(self, epfd: FileDescriptor[EpollFile], fd: FileDescriptor, event: Pointer) -> None:
        await raw_syscall.epoll_ctl(epfd.task.syscall, epfd.pure, EpollCtlOp.MOD, fd.pure, event)

    async def delete(self, epfd: FileDescriptor[EpollFile], fd: FileDescriptor) -> None:
        await raw_syscall.epoll_ctl(epfd.task.syscall, epfd.pure, EpollCtlOp.DEL, fd.pure)

    async def wait(self, epfd: FileDescriptor[EpollFile],
                   events: Pointer, maxevents: int, timeout: int) -> int:
        return (await raw_syscall.epoll_wait(epfd.task.syscall, epfd.pure, events, maxevents, timeout))

class SocketFile(t.Generic[T_addr], ReadableWritableFile):
    address_type: t.Type[T_addr]
    async def bind(self, fd: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: int) -> None:
        await raw_syscall.bind(fd.task.syscall, fd.pure, addr, addrlen)

    async def connect(self, fd: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: int) -> None:
        await raw_syscall.connect(fd.task.syscall, fd.pure, addr, addrlen)

    async def listen(self, fd: FileDescriptor[SocketFile], backlog: int) -> None:
        await raw_syscall.listen(fd.task.syscall, fd.pure, backlog)

    async def getsockname(self, fd: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: Pointer) -> None:
        await raw_syscall.getsockname(fd.task.syscall, fd.pure, addr, addrlen)

    async def getpeername(self, fd: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: Pointer) -> None:
        await raw_syscall.getpeername(fd.task.syscall, fd.pure, addr, addrlen)

    async def getsockopt(self, fd: FileDescriptor[SocketFile[T_addr]], level: int, optname: int,
                         optval: Pointer, optlen: Pointer) -> None:
        await raw_syscall.getsockopt(fd.task.syscall, fd.pure, level, optname, optval, optlen)

    async def setsockopt(self, fd: FileDescriptor[SocketFile[T_addr]], level: int, optname: int,
                         optval: Pointer, optlen: int) -> None:
        await raw_syscall.setsockopt(fd.task.syscall, fd.pure, level, optname, optval, optlen)

    async def accept(self, fd: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: Pointer, flags: int
    ) -> FileDescriptor[SocketFile[T_addr]]:
        fdnum = await raw_syscall.accept(fd.task.syscall, fd.pure, addr, addrlen, flags)
        return FileDescriptor(fd.task, base.FileDescriptor(fd.pure.fd_namespace, fdnum), SocketFile())

class UnixSocketFile(SocketFile[UnixAddress]):
    address_type = UnixAddress

class InetSocketFile(SocketFile[InetAddress]):
    address_type = InetAddress

class Task:
    def __init__(self, syscall: SyscallInterface,
                 fd_namespace: base.FDNamespace,
                 address_space: base.AddressSpace,
                 mount: base.MountNamespace,
                 fs: base.FSInformation,
                 sigmask: SignalMask,
                 process_namespace: base.ProcessNamespace,
    ) -> None:
        self.syscall = syscall
        self.fd_namespace = fd_namespace
        self.address_space = address_space
        self.mount = mount
        self.fs = fs
        self.sigmask = sigmask
        self.process_namespace = process_namespace

    async def close(self):
        await self.syscall.close_interface()

    async def exit(self, status: int) -> None:
        await raw_syscall.exit(self.syscall, status)
        await self.close()

    async def execveat(self, dirfd: t.Optional[FileDescriptor], path: Pointer,
                       argv: Pointer, envp: Pointer, flags: int) -> None:
        if dirfd is not None:
            assert dirfd.fd_namespace == self.fd_namespace
        assert path.address_space == self.address_space
        assert path.address_space == self.address_space
        assert path.address_space == self.address_space
        await raw_syscall.execveat(self.syscall, dirfd, path, argv, envp, flags)
        await self.close()

    async def unshare_fs(self) -> None:
        # we want this to return something that we can use to chdir
        raise NotImplementedError

    def _make_fd(self, num: int, file: T_file) -> FileDescriptor[T_file]:
        return FileDescriptor(self, base.FileDescriptor(self.fd_namespace, num), file)

    async def epoll_create(self, flags=lib.EPOLL_CLOEXEC) -> FileDescriptor[EpollFile]:
        epfd = await raw_syscall.epoll_create(self.syscall, flags)
        return self._make_fd(epfd, EpollFile())

    async def socket_unix(self, type: socket.SocketKind, protocol: int=0) -> FileDescriptor[UnixSocketFile]:
        sockfd = await raw_syscall.socket(self.syscall, lib.AF_UNIX, type, protocol)
        return self._make_fd(sockfd, UnixSocketFile())

    async def socket_inet(self, type: socket.SocketKind, protocol: int=0) -> FileDescriptor[InetSocketFile]:
        sockfd = await raw_syscall.socket(self.syscall, lib.AF_INET, type, protocol)
        return self._make_fd(sockfd, InetSocketFile())

    async def mmap(self, length: int, prot: memory.ProtFlag, flags: memory.MapFlag) -> memory.AnonymousMapping:
        # currently doesn't support specifying an address, nor specifying a file descriptor
        return (await memory.AnonymousMapping.make(
            self.syscall, self.address_space, length, prot, flags))

class FileDescriptor(t.Generic[T_file_co]):
    "A file descriptor, plus a task to access it from, plus the file object underlying the descriptor."
    task: Task
    pure: base.FileDescriptor
    file: T_file_co
    def __init__(self, task: Task, pure: base.FileDescriptor, file: T_file_co) -> None:
        self.task = task
        self.pure = pure
        self.file = file
        self.open = True

    async def close(self):
        if self.open:
            await raw_syscall.close(self.task.syscall, self.pure)
            self.open = False
        else:
            pass

    def __str__(self) -> str:
        return f"FD({self.task}, {self.pure}, {self.file})"

    async def __aenter__(self) -> FileDescriptor[T_file_co]:
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    async def dup2(self, target: FileDescriptor, flags: int=os.O_CLOEXEC) -> FileDescriptor[T_file_co]:
        """Make a copy of this file descriptor at target.number

        """
        if self.pure.fd_namespace != target.pure.fd_namespace:
            raise Exception("two fds are not in the same FDNamespace")
        if self is target:
            return self
        await raw_syscall.dup3(self.task.syscall, self.pure, target.pure, flags)
        target.open = False
        new_fd = self.task._make_fd(target.pure.number, self.file)
        self.file.shared = not(flags & os.O_CLOEXEC)
        return new_fd

    async def enable_cloexec(self) -> None:
        raise NotImplementedError

    async def disable_cloexec(self) -> None:
        await self.fcntl(fcntl.F_SETFD, 0)

    async def fcntl(self, cmd: int, arg: t.Union[Pointer, int]) -> int:
        return (await raw_syscall.fcntl(self.task.syscall, self.pure, cmd, arg))

    # These are just helper methods which forward to the method on the underlying file object.
    async def set_nonblock(self: FileDescriptor[File]) -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        await self.file.set_nonblock(self)

    async def read(self: FileDescriptor[ReadableFile], buf: Pointer, count: int) -> int:
        return (await self.file.read(self, buf, count))

    async def write(self, fd: FileDescriptor[WritableFile], buf: Pointer, count: int) -> int:
        return (await self.file.write(self, buf, count))

    async def epoll_add(self: FileDescriptor[EpollFile], fd: FileDescriptor, event: Pointer) -> None:
        await self.file.add(self, fd, event)

    async def epoll_modify(self: FileDescriptor[EpollFile], fd: FileDescriptor, event: Pointer) -> None:
        await self.file.modify(self, fd, event)

    async def epoll_delete(self: FileDescriptor[EpollFile], fd: FileDescriptor) -> None:
        await self.file.delete(self, fd)

    async def epoll_wait(self: FileDescriptor[EpollFile], events: Pointer, maxevents: int, timeout: int) -> int:
        return (await self.file.wait(self, events, maxevents, timeout))

    async def getdents(self: FileDescriptor[DirectoryFile], dirp: Pointer, count: int) -> int:
        return (await self.file.getdents(self, dirp, count))

    async def lseek(self: FileDescriptor[SeekableFile], offset: int, whence: int) -> int:
        return (await self.file.lseek(self, offset, whence))

    async def signalfd(self: FileDescriptor[SignalFile], mask: Pointer, sizemask: int) -> None:
        await self.file.signalfd(self, mask, sizemask)

    async def bind(self: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: int) -> None:
        await self.file.bind(self, addr, addrlen)

    async def connect(self: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: int) -> None:
        await self.file.connect(self, addr, addrlen)

    async def listen(self: FileDescriptor[SocketFile], backlog: int) -> None:
        await self.file.listen(self, backlog)

    async def getsockname(self: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: Pointer) -> None:
        return (await self.file.getsockname(self, addr, addrlen))

    async def getpeername(self: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: Pointer) -> None:
        return (await self.file.getpeername(self, addr, addrlen))

    async def getsockopt(self: FileDescriptor[SocketFile[T_addr]], level: int, optname: int,
                         optval: Pointer, optlen: Pointer) -> None:
        return (await self.file.getsockopt(self, level, optname, optval, optlen))

    async def accept(self: FileDescriptor[SocketFile[T_addr]], addr: Pointer[T_addr], addrlen: Pointer, flags: int
    ) -> FileDescriptor[SocketFile[T_addr]]:
        return (await self.file.accept(self, addr, addrlen, flags))
