"""Definitions of namespace-local identifiers, syscalls, and SyscallInterface

These namespace-local identifiers are like near pointers, in systems
with segmented memory. They are valid only within a specific segment
(namespace).

The syscalls are instructions, operating on near pointers and other
arguments.

The SyscallInterface is the segment register override prefix, which is
used with the instruction to say which segment register to use for the
syscall.

We don't know from a segment register override prefix alone that the
near pointers we are passing to an instruction are valid pointers in
the segment currently contained in the segment register.

In terms of our actual classes: We don't know from a SyscallInterface
alone that the identifiers we are passing to a syscall match the
namespaces active in the task behind the SyscallInterface.

(The task is like the segment register, in this analogy.)

"""

from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import enum
import abc
import logging
import trio
import typing as t
logger = logging.getLogger(__name__)

from rsyscall.fcntl import AT, F
from rsyscall.sys.wait import IdType
if t.TYPE_CHECKING:
    from rsyscall.sys.epoll import EPOLL_CTL
    from rsyscall.sys.prctl import PR
    from rsyscall.sys.socket import SHUT
    from rsyscall.sys.uio import RWF
    from rsyscall.sched import CLONE
    from rsyscall.signal import HowSIG, SIG
    import rsyscall.handle as handle

class SyscallInterface:
    """The lowest-level interface for an object which lets us send syscalls to some process

    We send syscalls to a process, but nothing in this interface tells us anything about
    the process to which we're sending syscalls; that information is maintained in the
    Task, which contains an object matching this interface.

    This is like the segment register override prefix, with no awareness of the contents
    of the register.

    """
    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        """Send a syscall and wait for it to complete, throwing on error results

        We provide a guarantee that if the syscall was sent to the process, then we will
        not return until the syscall has completed or our connection has broken.  To
        achieve this, we shield against Python coroutine cancellation while waiting for
        the syscall response.

        This guarantee is important so that our caller can deal with state changes caused
        by the syscall. If our coroutine was cancelled in the middle of a syscall, the
        result of the syscall would be discarded, and our caller wouldn't be able to
        guarantee that state changes in the process are reflected in state changes in
        Python.

        For example, a coroutine calling waitid could be cancelled; if that happened, we
        could discard a child state change indicating that the child exited. If that
        happened, future calls to waitid on that child would be invalid, or maybe return
        events for an unrelated child. We'd be completely confused.

        Instead, thanks to our guarantee, syscalls made through this method can be treated
        as atomic: They will either be submitted and completed, or not submitted at all.
        (If they're submitted and not completed due to blocking forever, that just means
        we'll never return.) There's no possibility of making a syscall, causing a
        side-effect, and never learning about the side-effect you caused.

        Since most syscalls use this method, this guarantee applies to most syscalls.

        For callers who want to preserve the ability for their coroutine to be cancelled
        even while waiting for a syscall response, the `submit_syscall` API can be used.

        Note that this Python-level cancellation protection has nothing to do with
        actually cancelling a syscall. That ability is still preserved with this
        interface; just send a signal to trigger an EINTR in the syscalling process, and
        we'll get back that EINTR as the syscall response. If you just want to be able to
        cancel deadlocked processes, you should do that.

        Likewise, if the rsyscall server dies, or we get an EOF on the syscall connection,
        or any other event causes response.receive to throw an exception, we'll still
        return that exception; so you can always fall back on killing the rsyscall server
        to stop a deadlock.

        """
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            with trio.CancelScope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

    @abc.abstractmethod
    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        """Submit a syscall without immediately waiting for its response to come back

        By calling `receive` on SyscallResponse, the caller can wait for the response.

        The primary purpose of this interface is to allow for cancellation. The `syscall`
        method doesn't allow cancellation while waiting for a syscall response. This
        method doesn't wait for the syscall response, and so can be used in scenarios
        where we want to avoid blocking for unneeded syscall responses.

        This interface is not for parallelization or concurrency. The `syscall` method can
        already be called concurrently from multiple coroutines; using this method does
        not give any improved performance characteristics compared to just spinning up
        multiple coroutines to call `syscall` in parallel.

        While this interface does allow the user to avoid blocking for the syscall
        response, using that as an optimization is obviously a bad idea. For correctness,
        you must eventually block for the syscall response to make sure the syscall
        succeeded. Appropriate usage of coroutines allows continuing operation without
        waiting for the syscall response even with `syscall`, while still enforcing that
        eventually we will examine the response.

        """
        pass

    # non-syscall operations which we haven't figured out how to get rid of yet
    logger: logging.Logger

    @abc.abstractmethod
    async def close_interface(self) -> None:
        "Close this syscall interface, shutting down the connection to the remote process"
        pass

    @abc.abstractmethod
    def get_activity_fd(self) -> t.Optional[handle.FileDescriptor]:
        """When this file descriptor is readable, it means other things want to run on this thread

        Users of the SyscallInterface should ensure that when they block, they are
        monitoring this fd as well.

        Typically, this is the file descriptor which the rsyscall server reads for
        incoming syscalls.

        """
        pass

class SyscallResponse:
    "A representation of the pending response to some syscall submitted through `submit_syscall`"
    @abc.abstractmethod
    async def receive(self) -> int:
        "Wait for the corresponding syscall to complete and return its result, throwing on error results"
        pass

#### Identifiers (near pointers)
@dataclass(frozen=True)
class FileDescriptor:
    """The integer identifier for a file descriptor taken by many syscalls

    This is a file descriptor in a specific file descriptor table, but we don't with this
    object know what file descriptor table that is.

    """
    number: int

    def __str__(self) -> str:
        return f"FD({self.number})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.number

@dataclass(frozen=True)
class WatchDescriptor:
    """The integer identifier for an inotify watch descriptor taken by inotify syscalls

    This is a watch descriptor for a specific inotify instance, but we don't with this
    object know what inotify instance that is.

    """
    number: int

    def __str__(self) -> str:
        return f"WD({self.number})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.number

@dataclass
class Address:
    """The integer identifier for a virtual memory address as taken by many syscalls

    This is an address in a specific address space, but we don't with this object know
    what address space that is.

    """
    address: int

    def __add__(self, other: int) -> 'Address':
        return Address(self.address + other)

    def __sub__(self, other: int) -> 'Address':
        return Address(self.address - other)

    def __str__(self) -> str:
        return f"Address({hex(self.address)})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.address

@dataclass
class MemoryMapping:
    """The integer identifiers for a virtual memory mapping as taken by many syscalls

    This is a mapping in a specific address space, but we don't with this object know what
    address space that is.

    We require three pieces of information to describe a memory mapping. 
    - Address is the start address of the memory mapping
    - Length is the length in bytes of the memory mapped region

    Page size is unusual, but required for robustness: While the syscalls related to
    memory mappings don't appear to depend on page size, that's an illusion. They seem to
    deal in sizes in terms of bytes, but if you provide a size which is not a multiple of
    the page size, silent failures or misbehaviors will occur. Misbehavior include the
    sizes being rounded up to the page size, including in munmap, thus unmapping more
    memory than expected.

    As long as we ensure that the original length we pass to mmap is a multiple of the
    page size that will be used for the mapping, then we could get by with just storing
    the length and not the page size. However, the memory mapping API allows unmapping
    only part of a mapping, or in general performing operations on only part of a
    mapping. These splits must happen at page boundaries, and therefore to support
    specifying these splits without allowing silent rounding errors, we need to know the
    page size of the mapping.

    This is especially troubling when mmaping files with an unknown page size, such as
    those passed to us from another program. memfd_create or hugetlbfs can be used to
    create files with an unknown page size, which cannot be robust unmapped. At this time,
    we don't know of a way to learn the page size of such a file. One good solution would
    be for mmap to be taught a new MAP_ENFORCE_PAGE_SIZE flag which requires MAP_HUGE_* to
    be passed when mapping files with nonstandard page size. In this way, we could assert
    the page size of the file and protect against attackers sending us files with
    unexpected page sizes.

    """
    address: int
    length: int
    page_size: int

    def __post_init_(self) -> None:
        if (self.address % self.page_size) != 0:
            raise Exception("the address for this memory-mapping is not page-aligned", self)
        if (self.length % self.page_size) != 0:
            raise Exception("the length for this memory-mapping is not page-aligned", self)

    def as_address(self) -> Address:
        "Return the starting address of this memory mapping"
        return Address(self.address)

    def __str__(self) -> str:
        if self.page_size == 4096:
            return f"MMap({hex(self.address)}, {self.length})"
        else:
            return f"MMap(pgsz={self.page_size}, {hex(self.address)}, {self.length})"

    def __repr__(self) -> str:
        return str(self)

@dataclass
class Process:
    """The integer identifier for a process taken by many syscalls

    This is a process in a specific pid namespace, but we don't with this object know what
    pid namespace that is.

    """
    id: int

    def __int__(self) -> int:
        return self.id

@dataclass
class ProcessGroup:
    """The integer identifier for a process group taken by many syscalls

    This is a process group in a specific pid namespace, but we don't with this object
    know what pid namespace that is.

    """
    id: int

    def __int__(self) -> int:
        return self.id

#### Syscalls (instructions)
# These are like instructions, run with this segment register override prefix and arguments.
import trio
from rsyscall.tasks.exceptions import RsyscallHangup
class SYS(enum.IntEnum):
    """The syscall number argument passed to the low-level `syscall` method and underlying instruction

    Passing one of these numbers is how a userspace program indicates to the kernel which
    syscall it wants to call.

    """
    accept4 = lib.SYS_accept4
    bind = lib.SYS_bind
    capget = lib.SYS_capget
    capset = lib.SYS_capset
    chdir = lib.SYS_chdir
    clone = lib.SYS_clone
    close = lib.SYS_close
    connect = lib.SYS_connect
    dup3 = lib.SYS_dup3
    epoll_create1 = lib.SYS_epoll_create1
    epoll_ctl = lib.SYS_epoll_ctl
    epoll_wait = lib.SYS_epoll_wait
    execveat = lib.SYS_execveat
    exit = lib.SYS_exit
    faccessat = lib.SYS_faccessat
    fchdir = lib.SYS_fchdir
    fchmod = lib.SYS_fchmod
    fcntl = lib.SYS_fcntl
    ftruncate = lib.SYS_ftruncate
    getdents64 = lib.SYS_getdents64
    getgid = lib.SYS_getgid
    getpeername = lib.SYS_getpeername
    getpgid = lib.SYS_getpgid
    getsockname = lib.SYS_getsockname
    getsockopt = lib.SYS_getsockopt
    getuid = lib.SYS_getuid
    inotify_add_watch = lib.SYS_inotify_add_watch
    inotify_init1 = lib.SYS_inotify_init1
    inotify_rm_watch = lib.SYS_inotify_rm_watch
    ioctl = lib.SYS_ioctl
    kill = lib.SYS_kill
    linkat = lib.SYS_linkat
    listen = lib.SYS_listen
    lseek = lib.SYS_lseek
    memfd_create = lib.SYS_memfd_create
    mkdirat = lib.SYS_mkdirat
    mmap = lib.SYS_mmap
    mount = lib.SYS_mount
    munmap = lib.SYS_munmap
    openat = lib.SYS_openat
    pipe2 = lib.SYS_pipe2
    prctl = lib.SYS_prctl
    pread64 = lib.SYS_pread64
    preadv2 = lib.SYS_preadv2
    pwritev2 = lib.SYS_pwritev2
    read = lib.SYS_read
    readlinkat = lib.SYS_readlinkat
    recvfrom = lib.SYS_recvfrom
    recvmsg = lib.SYS_recvmsg
    renameat2 = lib.SYS_renameat2
    rt_sigaction = lib.SYS_rt_sigaction
    rt_sigprocmask = lib.SYS_rt_sigprocmask
    sendmsg = lib.SYS_sendmsg
    set_robust_list = lib.SYS_set_robust_list
    set_tid_address = lib.SYS_set_tid_address
    setns = lib.SYS_setns
    setpgid = lib.SYS_setpgid
    setsid = lib.SYS_setsid
    setsockopt = lib.SYS_setsockopt
    shutdown = lib.SYS_shutdown
    signalfd4 = lib.SYS_signalfd4
    socket = lib.SYS_socket
    socketpair = lib.SYS_socketpair
    symlinkat = lib.SYS_symlinkat
    unlinkat = lib.SYS_unlinkat
    unshare = lib.SYS_unshare
    waitid = lib.SYS_waitid
    write = lib.SYS_write

async def accept4(sysif: SyscallInterface, sockfd: FileDescriptor,
                  addr: t.Optional[Address], addrlen: t.Optional[Address], flags: int) -> FileDescriptor:
    if addr is None:
        addr = 0 # type: ignore
    if addrlen is None:
        addrlen = 0 # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.accept4, sockfd, addr, addrlen, flags))

async def bind(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: int) -> None:
    await sysif.syscall(SYS.bind, sockfd, addr, addrlen)

async def capget(sysif: SyscallInterface, hdrp: Address, datap: Address) -> None:
    await sysif.syscall(SYS.capget, hdrp, datap)

async def capset(sysif: SyscallInterface, hdrp: Address, datap: Address) -> None:
    await sysif.syscall(SYS.capset, hdrp, datap)

async def chdir(sysif: SyscallInterface, path: Address) -> None:
    await sysif.syscall(SYS.chdir, path)

async def clone(sysif: SyscallInterface, flags: int, child_stack: Address,
                ptid: t.Optional[Address], ctid: t.Optional[Address],
                newtls: t.Optional[Address]) -> Process:
    # I don't use CLONE_THREAD, so I can say without confusion, that clone returns a Process.
    if child_stack is None:
        child_stack = 0 # type: ignore
    if ptid is None:
        ptid = 0 # type: ignore
    if ctid is None:
        ctid = 0 # type: ignore
    if newtls is None:
        newtls = 0 # type: ignore
    return Process(await sysif.syscall(SYS.clone, flags, child_stack, ptid, ctid, newtls))

async def close(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    await sysif.syscall(SYS.close, fd)

async def connect(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: int) -> None:
    await sysif.syscall(SYS.connect, sockfd, addr, addrlen)

async def dup3(sysif: SyscallInterface, oldfd: FileDescriptor, newfd: FileDescriptor, flags: int) -> None:
    await sysif.syscall(SYS.dup3, oldfd, newfd, flags)

async def epoll_create(sysif: SyscallInterface, flags: int) -> FileDescriptor:
    return FileDescriptor(await sysif.syscall(SYS.epoll_create1, flags))

async def epoll_ctl(sysif: SyscallInterface, epfd: FileDescriptor, op: EPOLL_CTL,
                    fd: FileDescriptor, event: t.Optional[Address]=None) -> None:
    if event is None:
        event = 0 # type: ignore
    await sysif.syscall(SYS.epoll_ctl, epfd, op, fd, event)

async def epoll_wait(sysif: SyscallInterface, epfd: FileDescriptor, events: Address, maxevents: int, timeout: int) -> int:
    return (await sysif.syscall(SYS.epoll_wait, epfd, events, maxevents, timeout))

async def execveat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Address,
                   argv: Address, envp: Address, flags: int) -> None:
    logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    def handle(exn):
        if isinstance(exn, RsyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execveat, dirfd, path, argv, envp, flags)

async def exit(sysif: SyscallInterface, status: int) -> None:
    def handle(exn):
        if isinstance(exn, RsyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.exit, status)

async def faccessat(sysif: SyscallInterface,
                    dirfd: t.Optional[FileDescriptor], path: Address, flags: int, mode: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.faccessat, dirfd, path, flags, mode)

async def fchdir(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    await sysif.syscall(SYS.fchdir, fd)

async def fchmod(sysif: SyscallInterface, fd: FileDescriptor, mode: int) -> None:
    await sysif.syscall(SYS.fchmod, fd, mode)

async def fcntl(sysif: SyscallInterface, fd: FileDescriptor, cmd: F, arg: t.Optional[t.Union[int, Address]]=None) -> int:
    logger.debug("fcntl(%s, %s, %s)", fd, cmd, arg)
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.fcntl, fd, cmd, arg))

async def ftruncate(sysif: SyscallInterface, fd: FileDescriptor, length: int) -> None:
    await sysif.syscall(SYS.ftruncate, fd, length)

async def getdents64(sysif: SyscallInterface, fd: FileDescriptor, dirp: Address, count: int) -> int:
    return (await sysif.syscall(SYS.getdents64, fd, dirp, count))

async def getgid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getgid))

async def getpeername(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: Address) -> None:
    await sysif.syscall(SYS.getpeername, sockfd, addr, addrlen)

async def getpgid(sysif: SyscallInterface, pid: t.Optional[Process]) -> ProcessGroup:
    if pid is None:
        pid = 0 # type: ignore
    return ProcessGroup(await sysif.syscall(SYS.getpgid, pid))

async def getsockname(sysif: SyscallInterface, sockfd: FileDescriptor, addr: Address, addrlen: Address) -> None:
    await sysif.syscall(SYS.getsockname, sockfd, addr, addrlen)

async def getsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int, optval: Address, optlen: Address) -> None:
    await sysif.syscall(SYS.getsockopt, sockfd, level, optname, optval, optlen)

async def getuid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getuid))

async def inotify_add_watch(sysif: SyscallInterface, fd: FileDescriptor, pathname: Address, mask: int) -> WatchDescriptor:
    return WatchDescriptor(await sysif.syscall(SYS.inotify_add_watch, fd, pathname, mask))

async def inotify_init(sysif: SyscallInterface, flags: int) -> FileDescriptor:
    return FileDescriptor(await sysif.syscall(SYS.inotify_init1, flags))

async def inotify_rm_watch(sysif: SyscallInterface, fd: FileDescriptor, wd: WatchDescriptor) -> None:
    await sysif.syscall(SYS.inotify_rm_watch, fd, wd)

async def ioctl(sysif: SyscallInterface, fd: FileDescriptor, request: int,
                arg: t.Optional[t.Union[int, Address]]=None) -> int:
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.ioctl, fd, request, arg))

async def kill(sysif: SyscallInterface, pid: t.Union[Process, ProcessGroup], sig: SIG) -> None:
    if isinstance(pid, ProcessGroup):
        pid = -int(pid) # type: ignore
    await sysif.syscall(SYS.kill, pid, sig)

async def linkat(sysif: SyscallInterface,
                 olddirfd: t.Optional[FileDescriptor], oldpath: Address,
                 newdirfd: t.Optional[FileDescriptor], newpath: Address,
                 flags: int) -> None:
    if olddirfd is None:
        olddirfd = AT.FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.linkat, olddirfd, oldpath, newdirfd, newpath, flags)

async def listen(sysif: SyscallInterface, sockfd: FileDescriptor, backlog: int) -> None:
    await sysif.syscall(SYS.listen, sockfd, backlog)

async def lseek(sysif: SyscallInterface, fd: FileDescriptor, offset: int, whence: int) -> int:
    return (await sysif.syscall(SYS.lseek, fd, offset, whence))

async def memfd_create(sysif: SyscallInterface, name: Address, flags: int) -> FileDescriptor:
    ret = await sysif.syscall(SYS.memfd_create, name, flags)
    return FileDescriptor(ret)

async def mkdirat(sysif: SyscallInterface,
                  dirfd: t.Optional[FileDescriptor], path: Address, mode: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.mkdirat, dirfd, path, mode)

async def mmap(sysif: SyscallInterface, length: int, prot: int, flags: int,
               addr: t.Optional[Address]=None, 
               fd: t.Optional[FileDescriptor]=None, offset: int=0,
               page_size: int=4096) -> MemoryMapping:
    if addr is None:
        addr = 0 # type: ignore
    else:
        assert (int(addr) % page_size) == 0
    if fd is None:
        fd = -1 # type: ignore
    # TODO we want Linux to enforce this for us, but instead it just rounds,
    # leaving us unable to later munmap.
    assert (int(length) % page_size) == 0
    ret = await sysif.syscall(SYS.mmap, addr, length, prot, flags, fd, offset)
    return MemoryMapping(address=ret, length=length, page_size=page_size)

async def mount(sysif: SyscallInterface, source: Address, target: Address,
                filesystemtype: Address, mountflags: int,
                data: Address) -> None:
    await sysif.syscall(SYS.mount, source, target, filesystemtype, mountflags, data)

async def munmap(sysif: SyscallInterface, mapping: MemoryMapping) -> None:
    await sysif.syscall(SYS.munmap, mapping.address, mapping.length)

async def openat(sysif: SyscallInterface, dirfd: t.Optional[FileDescriptor],
                 path: Address, flags: int, mode: int) -> FileDescriptor:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.openat, dirfd, path, flags, mode))

async def pipe2(sysif: SyscallInterface, pipefd: Address, flags: int) -> None:
    await sysif.syscall(SYS.pipe2, pipefd, flags)

async def prctl(sysif: SyscallInterface, option: PR, arg2: int,
                arg3: t.Optional[int], arg4: t.Optional[int], arg5: t.Optional[int]) -> int:
    if arg3 is None:
        arg3 = 0
    if arg4 is None:
        arg4 = 0
    if arg5 is None:
        arg5 = 0
    return (await sysif.syscall(SYS.prctl, option, arg2, arg3, arg4, arg5))

async def pread(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int, offset: int) -> int:
    return (await sysif.syscall(SYS.pread64, fd, buf, count, offset))

async def preadv2(sysif: SyscallInterface, fd: FileDescriptor, iov: Address, iovcnt: int, offset: int, flags: RWF) -> int:
    return (await sysif.syscall(SYS.preadv2, fd, iov, iovcnt, offset, flags))

async def pwritev2(sysif: SyscallInterface, fd: FileDescriptor, iov: Address, iovcnt: int, offset: int, flags: RWF) -> int:
    return (await sysif.syscall(SYS.pwritev2, fd, iov, iovcnt, offset, flags))

async def read(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int) -> int:
    return (await sysif.syscall(SYS.read, fd, buf, count))

async def readlinkat(sysif: SyscallInterface,
                     dirfd: t.Optional[FileDescriptor], path: Address,
                     buf: Address, bufsiz: int) -> int:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    return (await sysif.syscall(SYS.readlinkat, dirfd, path, buf, bufsiz))

async def recv(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int, flags: int) -> int:
    return (await sysif.syscall(SYS.recvfrom, fd, buf, count, flags))

async def recvmsg(sysif: SyscallInterface, fd: FileDescriptor, msg: Address, flags: int) -> int:
    return (await sysif.syscall(SYS.recvmsg, fd, msg, flags))

async def renameat2(sysif: SyscallInterface,
                    olddirfd: t.Optional[FileDescriptor], oldpath: Address,
                    newdirfd: t.Optional[FileDescriptor], newpath: Address,
                    flags: int) -> None:
    if olddirfd is None:
        olddirfd = AT.FDCWD # type: ignore
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.renameat2, olddirfd, oldpath, newdirfd, newpath, flags)

async def rt_sigaction(sysif: SyscallInterface, signum: SIG,
                       act: t.Optional[Address],
                       oldact: t.Optional[Address],
                       size: int) -> None:
    if act is None:
        act = 0 # type: ignore
    if oldact is None:
        oldact = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigaction, signum, act, oldact, size)

async def rt_sigprocmask(sysif: SyscallInterface,
                         newset: t.Optional[t.Tuple[HowSIG, Address]],
                         oldset: t.Optional[Address],
                         sigsetsize: int) -> None:
    if newset is not None:
        how, set = newset
    else:
        how, set = 0, 0 # type: ignore
    if oldset is None:
        oldset = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigprocmask, how, set, oldset, sigsetsize)

async def sendmsg(sysif: SyscallInterface, fd: FileDescriptor, msg: Address, flags: int) -> int:
    return (await sysif.syscall(SYS.sendmsg, fd, msg, flags))

async def set_robust_list(sysif: SyscallInterface, head: Address, len: int) -> None:
    await sysif.syscall(SYS.set_robust_list, head, len)

async def set_tid_address(sysif: SyscallInterface, ptr: Address) -> None:
    await sysif.syscall(SYS.set_tid_address, ptr)

async def setns(sysif: SyscallInterface, fd: FileDescriptor, nstype: int) -> None:
    await sysif.syscall(SYS.setns, fd, nstype)

async def setpgid(sysif: SyscallInterface, pid: t.Optional[Process], pgid: t.Optional[ProcessGroup]) -> None:
    if pid is None:
        pid = 0 # type: ignore
    if pgid is None:
        pgid = 0 # type: ignore
    await sysif.syscall(SYS.setpgid, pid, pgid)

async def setsid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.setsid))

async def setsockopt(sysif: SyscallInterface, sockfd: FileDescriptor, level: int, optname: int,
                     optval: Address, optlen: int) -> None:
    await sysif.syscall(SYS.setsockopt, sockfd, level, optname, optval, optlen)

async def shutdown(sysif: SyscallInterface, sockfd: FileDescriptor, how: SHUT) -> None:
    await sysif.syscall(SYS.shutdown, sockfd, how)

async def signalfd4(sysif: SyscallInterface, fd: t.Optional[FileDescriptor],
                    mask: Address, sizemask: int, flags: int) -> FileDescriptor:
    if fd is None:
        fd = -1 # type: ignore
    return FileDescriptor(await sysif.syscall(SYS.signalfd4, fd, mask, sizemask, flags))

async def socket(sysif: SyscallInterface, domain: int, type: int, protocol: int) -> FileDescriptor:
    return FileDescriptor(await sysif.syscall(SYS.socket, domain, type, protocol))

async def socketpair(sysif: SyscallInterface, domain: int, type: int, protocol: int, sv: Address) -> None:
    await sysif.syscall(SYS.socketpair, domain, type, protocol, sv)

async def symlinkat(sysif: SyscallInterface,
                    target: Address, newdirfd: t.Optional[FileDescriptor], linkpath: Address) -> None:
    if newdirfd is None:
        newdirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.symlinkat, target, newdirfd, linkpath)

async def unlinkat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Address, flags: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    await sysif.syscall(SYS.unlinkat, dirfd, path, flags)

async def unshare(sysif: SyscallInterface, flags: CLONE) -> None:
    await sysif.syscall(SYS.unshare, flags)

async def waitid(sysif: SyscallInterface,
                 id: t.Union[Process, ProcessGroup, None], infop: t.Optional[Address], options: int,
                 rusage: t.Optional[Address]) -> int:
    logger.debug("waitid(%s, %s, %s, %s)", id, infop, options, rusage)
    if isinstance(id, Process):
        idtype = IdType.PID
    elif isinstance(id, ProcessGroup):
        idtype = IdType.PGID
    elif id is None:
        idtype = IdType.ALL
        id = 0 # type: ignore
    else:
        raise ValueError("unknown id type", id)
    if infop is None:
        infop = 0 # type: ignore
    if rusage is None:
        rusage = 0 # type: ignore
    return (await sysif.syscall(SYS.waitid, idtype, id, infop, options, rusage))

async def write(sysif: SyscallInterface, fd: FileDescriptor, buf: Address, count: int) -> int:
    return (await sysif.syscall(SYS.write, fd, buf, count))

