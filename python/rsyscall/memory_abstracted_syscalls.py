from rsyscall._raw import ffi, lib # type: ignore
import os
import rsyscall.raw_syscalls as raw_syscall
from rsyscall.base import SyscallInterface, MemoryGateway
import rsyscall.base as base
import rsyscall.memory as memory
import array
import typing as t
import logging
import struct
import signal
import contextlib
logger = logging.getLogger(__name__)

class SigprocmaskHow(enum.IntEnum):
    BLOCK = lib.SIG_BLOCK
    UNBLOCK = lib.SIG_UNBLOCK
    SETMASK = lib.SIG_SETMASK

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
async def chdir(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                path: bytes) -> None:
    logger.debug("chdir(%s)", path)
    async with localize_data(gateway, allocator, path+b"\0") as (path_ptr, _):
        await raw_syscall.chdir(sysif, path_ptr)

async def getdents64(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                   fd: base.FileDescriptor, count: int) -> bytes:
    logger.debug("getdents64(%s, %s)", fd, count)
    with await allocator.malloc(count) as dirp:
        ret = await raw_syscall.getdents(sysif, fd, dirp, count)
        return (await read_to_bytes(gateway, dirp, ret))

# sigset_t is just a 64bit bitmask of signals, I don't need the manipulation macros.
sigset = struct.Struct("Q")
async def signalfd(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                   mask: t.Set[signal.Signals], flags: int,
                   fd: t.Optional[base.FileDescriptor]=None) -> int:
    logger.debug("signalfd(%s, %s, %s)", mask, flags, fd)
    mask_integer = 0
    for sig in mask:
        mask_integer |= 1 << (sig-1)
    mask_data = sigset.pack(mask_integer)
    async with localize_data(gateway, allocator, mask_data) as (mask_ptr, mask_len):
        return (await raw_syscall.signalfd4(sysif, mask_ptr, mask_len, flags, fd=fd))

async def rt_sigprocmask(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                         newset: t.Optional[t.Tuple[SigprocmaskHow, t.Set[signal.Signals]]]=None,
                         want_oldset: bool=True,
) -> t.Set[signal.Signals]:
    logger.debug("rt_sigprocmask(%s, %s)", how, set)
    old_set = ffi.new('unsigned long*')
    if set is None:
        with await allocator.malloc(sigset.size) as old_set:
            await raw_syscall.rt_sigprocmask(sysif, how, ffi.NULL, old_set, sigset.size)
            # TODO need to read the bytes out
            # hmmmmm
    else:
        set_integer = 0
        for sig in set:
            set_integer |= 1 << (sig-1)
        new_set = ffi.new('unsigned long*', set_integer)
        await self.syscall(lib.SYS_rt_sigprocmask, how,
                           ffi.cast('long', new_set), ffi.cast('long', old_set),
                           ffi.sizeof('unsigned long'))
    return {signal.Signals(bit) for bit in bits(old_set[0])}


#### two syscalls returning a pair of integers ####
intpair = struct.Struct("II")

async def read_to_intpair(gateway: MemoryGateway, pair_ptr: base.Pointer) -> t.Tuple[int, int]:
    data = await read_to_bytes(gateway, pair_ptr, intpair.size)
    return intpair.unpack(data)

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
    if isinstance(path.base, base.RootPathBase):
        # pathname has to be null terminated
        pathname = b"/" + path.data + b"\0"
    else:
        pathname = path.data + b"\0"
    async with localize_data(gateway, allocator, pathname) as (pathname_ptr, pathname_len):
        if isinstance(path.base, base.DirfdPathBase):
            yield path.base.dirfd, pathname_ptr
        else:
            yield None, pathname_ptr

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
        local_buf = ffi.new('char[]', ret)
        await gateway.memcpy(base.to_local_pointer(ffi.buffer(local_buf)), buf, ret)
    return bytes(ffi.buffer(local_buf, ret))


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
