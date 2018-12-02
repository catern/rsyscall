from rsyscall._raw import ffi, lib # type: ignore
import trio
import os
import socket
import rsyscall.raw_syscalls as raw_syscall
from rsyscall.raw_syscalls import SigprocmaskHow, IdType
from rsyscall.base import SyscallInterface, MemoryGateway
from dataclasses import dataclass
import rsyscall.base as base
import rsyscall.far as far
import rsyscall.near as near
import rsyscall.epoll as epoll
import rsyscall.memory as memory
import array
import typing as t
import logging
import struct
import signal
import contextlib
import enum
logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

@contextlib.asynccontextmanager
async def localize_data(
        gateway: MemoryGateway, allocator: memory.Allocator, data: bytes
) -> t.AsyncGenerator[t.Tuple[base.Pointer, int], None]:
    data_len = len(data)
    with await allocator.malloc(data_len) as data_ptr:
        await gateway.memcpy(data_ptr, base.to_local_pointer(data), data_len)
        yield data_ptr, data_len

async def read_to_bytes(gateway: MemoryGateway, data: base.Pointer, count: int) -> bytes:
    local_data = ffi.new('char[]', count)
    await gateway.memcpy(base.to_local_pointer(ffi.buffer(local_data)), data, count)
    return bytes(ffi.buffer(local_data, count))


#### miscellaneous ####
async def read(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
               fd: far.FileDescriptor, count: int) -> bytes:
    logger.debug("read(%s, %s)", fd, count)
    with await allocator.malloc(count) as buf_ptr:
        ret = await far.read(task, fd, buf_ptr, count)
        with trio.open_cancel_scope(shield=True):
            return (await read_to_bytes(gateway, buf_ptr, ret))

async def write(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                fd: base.FileDescriptor, buf: bytes) -> int:
    logger.debug("write(%s, %s)", fd, buf)
    async with localize_data(gateway, allocator, buf) as (buf_ptr, buf_len):
        return (await raw_syscall.write(sysif, fd, buf_ptr, buf_len))

async def recv(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
               fd: far.FileDescriptor, count: int, flags: int) -> bytes:
    logger.debug("recv(%s, %s, %s)", fd, count, flags)
    with await allocator.malloc(count) as buf_ptr:
        ret = await far.recv(task, fd, buf_ptr, count, flags)
        return (await read_to_bytes(gateway, buf_ptr, ret))

async def memfd_create(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
                       name: bytes, flags: int) -> far.FileDescriptor:
    async with localize_data(gateway, allocator, name+b"\0") as (name_ptr, _):
        return (await far.memfd_create(task, name_ptr, flags))

async def getdents64(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
                     fd: far.FileDescriptor, count: int) -> bytes:
    logger.debug("getdents64(%s, %s)", fd, count)
    with await allocator.malloc(count) as dirp:
        ret = await far.getdents64(task, fd, dirp, count)
        return (await read_to_bytes(gateway, dirp, ret))

siginfo_size = ffi.sizeof('siginfo_t')
async def waitid(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                 id: t.Union[base.Process, base.ProcessGroup, None], options: int) -> bytes:
    logger.debug("waitid(%s, %s)", id, options)
    with await allocator.malloc(siginfo_size) as infop:
        await raw_syscall.waitid(sysif, id, infop, options, None)
        return (await read_to_bytes(gateway, infop, siginfo_size))


#### epoll ####
async def epoll_ctl_add(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
                        epfd: far.FileDescriptor, fd: far.FileDescriptor, event: epoll.EpollEvent) -> None:
    logger.debug("epoll_ctl_add(%s, %s, %s)", epfd, fd, event)
    async with localize_data(gateway, allocator, event.to_bytes()) as (event_ptr, _):
        await far.epoll_ctl(task, epfd, near.EpollCtlOp.ADD, fd, event_ptr)

async def epoll_ctl_mod(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
                        epfd: far.FileDescriptor, fd: far.FileDescriptor, event: epoll.EpollEvent) -> None:
    logger.debug("epoll_ctl_mod(%s, %s, %s)", epfd, fd, event)
    async with localize_data(gateway, allocator, event.to_bytes()) as (event_ptr, _):
        await far.epoll_ctl(task, epfd, near.EpollCtlOp.MOD, fd, event_ptr)

async def epoll_ctl_del(task: far.Task, epfd: far.FileDescriptor, fd: far.FileDescriptor) -> None:
    logger.debug("epoll_ctl_del(%s, %s)", epfd, fd)
    await far.epoll_ctl(task, epfd, near.EpollCtlOp.DEL, fd)


#### signal mask manipulation ####
# sigset_t is just a 64bit bitmask of signals, I don't need the manipulation macros.
sigset = struct.Struct("Q")
def sigset_to_bytes(set: t.Set[signal.Signals]) -> bytes:
    set_integer = 0
    for sig in set:
        set_integer |= 1 << (sig-1)
    return sigset.pack(set_integer)

async def signalfd(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                   mask: t.Set[signal.Signals], flags: int,
                   fd: t.Optional[base.FileDescriptor]=None) -> int:
    logger.debug("signalfd(%s, %s, %s)", mask, flags, fd)
    async with localize_data(gateway, allocator, sigset_to_bytes(mask)) as (mask_ptr, mask_len):
        return (await raw_syscall.signalfd4(sysif, mask_ptr, mask_len, flags, fd=fd))

def bits(n: int):
    "Yields the bit indices that are set in this integer"
    while n:
        b = n & (~n+1)
        yield b.bit_length()
        n ^= b

def bytes_to_sigset(data: bytes) -> t.Set[signal.Signals]:
    set_integer, = sigset.unpack(data)
    return {signal.Signals(bit) for bit in bits(set_integer)}

async def rt_sigprocmask(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                         how: SigprocmaskHow, newset: t.Set[signal.Signals]) -> t.Set[signal.Signals]:
    logger.debug("rt_sigprocmask(%s, %s)", how, set)
    async with localize_data(gateway, allocator, sigset_to_bytes(newset)) as (newset_ptr, _):
        with await allocator.malloc(sigset.size) as oldset_ptr:
            await raw_syscall.rt_sigprocmask(sysif, (how, newset_ptr), oldset_ptr, sigset.size)
            oldset_data = await read_to_bytes(gateway, oldset_ptr, sigset.size)
            return bytes_to_sigset(oldset_data)


#### two syscalls returning a pair of integers ####
intpair = struct.Struct("II")

async def read_to_intpair(gateway: MemoryGateway, pair_ptr: base.Pointer) -> t.Tuple[int, int]:
    data = await read_to_bytes(gateway, pair_ptr, intpair.size)
    a, b = intpair.unpack(data)
    return a, b

async def pipe(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
               flags: int) -> t.Tuple[int, int]:
    logger.debug("pipe(%s)", flags)
    with await allocator.malloc(intpair.size) as bufptr:
        await raw_syscall.pipe2(sysif, bufptr, flags)
        return (await read_to_intpair(gateway, bufptr))

async def socketpair(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                     domain: int, type: int, protocol: int) -> t.Tuple[int, int]:
    logger.debug("socketpair(%s, %s, %s)", domain, type, protocol)
    with await allocator.malloc(intpair.size) as bufptr:
        await raw_syscall.socketpair(sysif, domain, type, protocol, bufptr)
        return (await read_to_intpair(gateway, bufptr))


#### filesystem operations which take a dirfd and path ####
@contextlib.asynccontextmanager
async def localize_path(
        gateway: MemoryGateway, allocator: memory.Allocator, path: base.Path
) -> t.AsyncGenerator[t.Tuple[t.Optional[base.FileDescriptor], base.Pointer], None]:
    pathdata = b"/".join(path.components)
    if isinstance(path.base, base.RootPathBase):
        # pathname has to be null terminated
        pathname = b"/" + pathdata + b"\0"
    else:
        pathname = pathdata + b"\0"
    async with localize_data(gateway, allocator, pathname) as (pathname_ptr, pathname_len):
        if isinstance(path.base, base.DirfdPathBase):
            yield path.base.dirfd, pathname_ptr
        else:
            yield None, pathname_ptr

async def chdir(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                path: base.Path) -> None:
    logger.debug("chdir(%s)", path)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        if dirfd is not None:
            await raw_syscall.fchdir(sysif, dirfd)
        await raw_syscall.chdir(sysif, pathname)

async def openat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                 path: base.Path, flags: int, mode: int) -> int:
    logger.debug("openat(%s, %s, %s)", path, flags, mode)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        return (await raw_syscall.openat(sysif, dirfd, pathname, flags, mode))

async def faccessat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                    path: base.Path, flags: int, mode: int) -> None:
    # TODO
    # logger.debug("faccessat(%s, %s, %s)", path, flags, mode)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        await raw_syscall.faccessat(sysif, dirfd, pathname, flags, mode)

async def mkdirat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                  path: base.Path, mode: int) -> None:
    logger.debug("mkdirat(%s, %s)", path, mode)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        await raw_syscall.mkdirat(sysif, dirfd, pathname, mode)

async def unlinkat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                   path: base.Path, flags: int) -> None:
    logger.debug("unlinkat(%s, %s)", path, flags)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        await raw_syscall.unlinkat(sysif, dirfd, pathname, flags)

async def linkat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                 oldpath: base.Path, newpath: base.Path, flags: int) -> None:
    logger.debug("linkat(%s, %s, %s)", oldpath, newpath, flags)
    async with localize_path(gateway, allocator, oldpath) as (olddirfd, oldpathname):
        async with localize_path(gateway, allocator, newpath) as (newdirfd, newpathname):
            await raw_syscall.linkat(sysif, olddirfd, oldpathname, newdirfd, newpathname, flags)

async def renameat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                   oldpath: base.Path, newpath: base.Path, flags: int) -> None:
    logger.debug("renameat2(%s, %s, %s)", oldpath, newpath, flags)
    async with localize_path(gateway, allocator, oldpath) as (olddirfd, oldpathname):
        async with localize_path(gateway, allocator, newpath) as (newdirfd, newpathname):
            await raw_syscall.renameat2(sysif, olddirfd, oldpathname, newdirfd, newpathname, flags)

async def symlinkat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                    linkpath: base.Path, target: bytes) -> None:
    logger.debug("symlinkat(%s, %s)", linkpath, target)
    async with localize_path(gateway, allocator, linkpath) as (linkdirfd, linkpathname):
        async with localize_data(gateway, allocator, target+b"\0") as (target_ptr, _):
            await raw_syscall.symlinkat(sysif, linkdirfd, linkpathname, target_ptr)

async def readlinkat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                     path: base.Path, bufsiz: int) -> bytes:
    logger.debug("readlinkat(%s, %s)", path, bufsiz)
    with await allocator.malloc(bufsiz) as buf:
        async with localize_path(gateway, allocator, path) as (dirfd, pathname):
            ret = await raw_syscall.readlinkat(sysif, dirfd, pathname, buf, bufsiz)
        return (await read_to_bytes(gateway, buf, ret))


#### execveat, which requires a lot of memory fiddling ####
class SerializedPointer:
    def __init__(self, size: int) -> None:
        self.size = size
        self._real_pointer: t.Optional[base.Pointer] = None

    @property
    def pointer(self) -> base.Pointer:
        if self._real_pointer is None:
            raise Exception("SerializedPointer's pointer was accessed before it was actually allocated")
        else:
            return self._real_pointer

def align_pointer(ptr: base.Pointer, alignment: int) -> base.Pointer:
    misalignment = int(ptr) % alignment
    if misalignment == 0:
        return ptr
    else:
        return ptr + (alignment - misalignment)

@dataclass
class SerializerOperation:
    ptr: SerializedPointer
    data: t.Union[bytes, t.Callable[[], bytes], None]
    alignment: int = 1
    def __post_init__(self) -> None:
        assert self.alignment > 0

    def size_to_allocate(self) -> t.Optional[int]:
        if self.ptr._real_pointer is not None:
            return None
        else:
            return self.ptr.size + (self.alignment-1)

    def supply_allocation(self, ptr: base.Pointer) -> None:
        self.ptr._real_pointer = align_pointer(ptr, self.alignment)

    def data_to_copy(self) -> t.Optional[bytes]:
        if isinstance(self.data, bytes):
            return self.data
        elif callable(self.data):
            data_bytes = self.data()
            if len(data_bytes) != self.ptr.size:
                print(self.data)
                print(data_bytes)
                raise Exception("size provided", self.ptr.size, "doesn't match size of bytes",
                                len(data_bytes))
            return data_bytes
        elif self.data is None:
            return None
        else:
            raise Exception("nonsense value in operations", self.data)

class Serializer:
    def __init__(self) -> None:
        self.operations: t.List[SerializerOperation] = []

    def serialize_data(self, data: bytes) -> SerializedPointer:
        size = len(data)
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, data))
        return ptr

    def serialize_lambda(self, size: int, func: t.Callable[[], bytes], alignment=1) -> SerializedPointer:
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, func, alignment))
        return ptr

    def serialize_cffi(self, typ: str, func: t.Callable[[], t.Any]) -> SerializedPointer:
        size = ffi.sizeof(typ)
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, lambda: bytes(ffi.buffer(ffi.new(typ+"*", func())))))
        return ptr

    def serialize_uninitialized(self, size: int) -> SerializedPointer:
        ptr = SerializedPointer(size)
        self.operations.append(SerializerOperation(ptr, None))
        return ptr

    def serialize_preallocated(self, real_ptr: base.Pointer, data: bytes) -> SerializedPointer:
        size = len(data)
        ptr = SerializedPointer(size)
        ptr._real_pointer = real_ptr
        self.operations.append(SerializerOperation(ptr, data))
        return ptr

    @contextlib.asynccontextmanager
    async def with_flushed(self, gateway: MemoryGateway, allocator: memory.AllocatorInterface
    ) -> t.AsyncGenerator[None, None]:
        # some are already allocated, so we skip them
        needs_allocation: t.List[t.Tuple[SerializerOperation, int]] = []
        for op in self.operations:
            size = op.size_to_allocate()
            if size:
                needs_allocation.append((op, size))
        async with allocator.bulk_malloc([size for (op, size) in needs_allocation]) as pointers:
            for ptr, (op, _) in zip(pointers, needs_allocation):
                op.supply_allocation(ptr)
            real_operations: t.List[t.Tuple[base.Pointer, bytes]] = []
            for op in self.operations:
                data = op.data_to_copy()
                if data:
                    real_operations.append((op.ptr.pointer, data))
            # copy all the bytes in bulk
            await gateway.batch_memcpy([
                (ptr, base.to_local_pointer(data), len(data)) for ptr, data in real_operations
            ])
            yield

pointer = struct.Struct("Q")
def serialize_null_terminated_array(serializer: Serializer, args: t.List[bytes]) -> SerializedPointer:
    arg_ser_ptrs = [serializer.serialize_data(arg+b"\0") for arg in args]
    argv_ser_ptr = serializer.serialize_lambda(
        (len(args) + 1) * pointer.size,
        lambda: b"".join(pointer.pack(int(ser_ptr.pointer.near)) for ser_ptr in arg_ser_ptrs) + pointer.pack(0)
    )
    return argv_ser_ptr

async def execveat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                   path: base.Path, argv: t.List[bytes], envp: t.List[bytes], flags: int) -> None:
    logger.debug("execveat(%s, <len(argv): %d>, <len(envp): %d>, %s)", path, len(argv), len(envp), flags)
    # TODO we should batch this localize_path with the rest
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        serializer = Serializer()
        argv_ser_ptr = serialize_null_terminated_array(serializer, argv)
        envp_ser_ptr = serialize_null_terminated_array(serializer, envp)
        async with serializer.with_flushed(gateway, allocator):
            await raw_syscall.execveat(sysif, dirfd, pathname, argv_ser_ptr.pointer, envp_ser_ptr.pointer, flags)

async def sendmsg_fds(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
                      fd: far.FileDescriptor, send_fds: t.List[far.FileDescriptor]) -> None:
    serializer = Serializer()
    dummy_data = serializer.serialize_data(b"\0")
    iovec = serializer.serialize_cffi('struct iovec',
                                      lambda: (ffi.cast('void*', int(dummy_data.pointer)), 1))
    cmsg_fds_bytes = array.array('i',
                                 (int(task.to_near_fd(send_fd)) for send_fd in send_fds)).tobytes()
    cmsghdr = serializer.serialize_data(bytes(ffi.buffer(ffi.new(
        'struct cmsghdr*', (ffi.sizeof('struct cmsghdr')+len(cmsg_fds_bytes), socket.SOL_SOCKET, socket.SCM_RIGHTS)))
    ) + cmsg_fds_bytes)
    msghdr = serializer.serialize_cffi(
        'struct msghdr', lambda: (ffi.cast('void*', 0), 0,
                                  ffi.cast('void*', int(iovec.pointer)), 1,
                                  ffi.cast('void*', int(cmsghdr.pointer)), cmsghdr.size, 0))
    async with serializer.with_flushed(gateway, allocator):
        await far.sendmsg(task, fd, msghdr.pointer, msghdr.size)

async def recvmsg_fds(task: far.Task, gateway: MemoryGateway, allocator: memory.Allocator,
                      fd: far.FileDescriptor, num_fds: int) -> t.List[near.FileDescriptor]:
    serializer = Serializer()
    data_buf = serializer.serialize_uninitialized(1)
    iovec = serializer.serialize_cffi(
        'struct iovec', lambda: (ffi.cast('void*', int(data_buf.pointer)), data_buf.size))
    local_fds_buf = array.array('i', [0]*num_fds)
    address, length = local_fds_buf.buffer_info()
    buf_len = length * local_fds_buf.itemsize
    cmsgbuf = serializer.serialize_uninitialized(ffi.sizeof('struct cmsghdr') + buf_len)
    msghdr = serializer.serialize_cffi(
        'struct msghdr', lambda: (ffi.cast('void*', 0), 0,
                                  ffi.cast('void*', int(iovec.pointer)), 1,
                                  ffi.cast('void*', int(cmsgbuf.pointer)), cmsgbuf.size, 0))
    async with serializer.with_flushed(gateway, allocator):
        await far.recvmsg(task, fd, msghdr.pointer, msghdr.size)
        fds_buf = cmsgbuf.pointer + ffi.sizeof('struct cmsghdr')
        # hmm it would be nice to pass near pointers here
        # that implies that we should request a specific gateway for a pair of address spaces,
        # then call a function.
        await gateway.memcpy(base.Pointer(base.local_address_space, near.Pointer(address)),
                             fds_buf, buf_len)
        return [near.FileDescriptor(fd) for fd in local_fds_buf]


#### socket syscalls that write data ####
async def setsockopt(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                     sockfd: base.FileDescriptor, level: int, optname: int, optval: bytes) -> None:
    logger.debug("setsockopt(%s, %s, %s, %s)", sockfd, level, optname, optval)
    async with localize_data(gateway, allocator, optval) as (optval_ptr, optlen):
        await raw_syscall.setsockopt(sysif, sockfd, level, optname, optval_ptr, optlen)

async def bind(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
               sockfd: base.FileDescriptor, addr: bytes) -> None:
    logger.debug("bind(%s, %s)", sockfd, addr)
    async with localize_data(gateway, allocator, addr) as (addr_ptr, addr_len):
        await raw_syscall.bind(sysif, sockfd, addr_ptr, addr_len)

async def connect(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                  sockfd: base.FileDescriptor, addr: bytes) -> None:
    logger.debug("connect(%s, %s)", sockfd, addr)
    async with localize_data(gateway, allocator, addr) as (addr_ptr, addr_len):
        await raw_syscall.connect(sysif, sockfd, addr_ptr, addr_len)


#### socket syscalls that read data, which all use a socklen value-result argument ####
socklen = struct.Struct("Q")
@contextlib.asynccontextmanager
async def alloc_sockbuf(
        gateway: MemoryGateway, allocator: memory.Allocator, buflen: int
) -> t.AsyncGenerator[t.Tuple[base.Pointer, base.Pointer], None]:
    # TODO we should batch these allocations together
    with await allocator.malloc(buflen) as buf_ptr:
        buflen_data = socklen.pack(buflen)
        async with localize_data(gateway, allocator, buflen_data) as (buflen_ptr, buflen_len):
            yield buf_ptr, buflen_ptr

async def read_sockbuf(
        gateway: MemoryGateway, buf_ptr: base.Pointer, buflen: int, buflen_ptr: base.Pointer
) -> bytes:
    # TODO we should optimize this to just do a single batch memcpy
    buflen_data = await read_to_bytes(gateway, buflen_ptr, socklen.size)
    buflen_result, = socklen.unpack(buflen_data)
    buf = await read_to_bytes(gateway, buf_ptr, buflen_result)
    return buf

async def getsockname(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                      sockfd: base.FileDescriptor, addrlen: int) -> bytes:
    logger.debug("getsockname(%s, %s)", sockfd, addrlen)
    async with alloc_sockbuf(gateway, allocator, addrlen) as (addr_ptr, addrlen_ptr):
        # uggghh, the socket api requires a write before, a syscall, and a read after - so much overhead!
        # whyyy doesn't it just return the possible read length as an integer?
        await raw_syscall.getsockname(sysif, sockfd, addr_ptr, addrlen_ptr)
        return (await read_sockbuf(gateway, addr_ptr, addrlen, addrlen_ptr))

async def getpeername(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                      sockfd: base.FileDescriptor, addrlen: int) -> bytes:
    logger.debug("getpeername(%s, %s)", sockfd, addrlen)
    async with alloc_sockbuf(gateway, allocator, addrlen) as (addr_ptr, addrlen_ptr):
        await raw_syscall.getpeername(sysif, sockfd, addr_ptr, addrlen_ptr)
        return (await read_sockbuf(gateway, addr_ptr, addrlen, addrlen_ptr))

async def getsockopt(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                     sockfd: base.FileDescriptor, level: int, optname: int, optlen: int) -> bytes:
    logger.debug("getsockopt(%s, %s, %s, %s)", sockfd, level, optname, optlen)
    async with alloc_sockbuf(gateway, allocator, optlen) as (opt_ptr, optlen_ptr):
        await raw_syscall.getsockopt(sysif, sockfd, level, optname, opt_ptr, optlen_ptr)
        return (await read_sockbuf(gateway, opt_ptr, optlen, optlen_ptr))

async def accept(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                 sockfd: base.FileDescriptor, addrlen: int, flags: int) -> t.Tuple[int, bytes]:
    logger.debug("accept(%s, %s, %s)", sockfd, addrlen, flags)
    async with alloc_sockbuf(gateway, allocator, addrlen) as (addr_ptr, addrlen_ptr):
        fd = await raw_syscall.accept(sysif, sockfd, addr_ptr, addrlen_ptr, flags)
        addr = await read_sockbuf(gateway, addr_ptr, addrlen, addrlen_ptr)
        return fd, addr
