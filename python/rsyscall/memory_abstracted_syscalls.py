from rsyscall._raw import ffi, lib # type: ignore
import os
import rsyscall.raw_syscalls as raw_syscall
from rsyscall.base import SyscallInterface, MemoryGateway
import rsyscall.base as base
import rsyscall.memory as memory
import array
import typing as t
import logging
import contextlib
logger = logging.getLogger(__name__)

async def pipe(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator, flags: int) -> t.Tuple[int, int]:
    logger.debug("pipe(%s)", flags)
    # TODO should I use array instead of ffi?
    localbuf = ffi.new('int[2]')
    bufsize = ffi.sizeof(localbuf)
    with await allocator.malloc(bufsize) as bufptr:
        await raw_syscall.pipe2(sysif, bufptr, flags)
        await gateway.memcpy(base.to_local_pointer(ffi.buffer(localbuf)), bufptr, bufsize)
    return (localbuf[0], localbuf[1])

async def getname_helper(name: str, raw_syscall_func,
                         sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                         sockfd: base.FileDescriptor, addrlen: int) -> bytes:
    logger.debug("%s(%s, %s)", name, sockfd, addrlen)
    local_addr_buf = ffi.new('char[]', addrlen)
    local_addrlen_buf = ffi.new('size_t*', addrlen)
    addrlen_buflen = ffi.sizeof(local_addrlen_buf)
    # TODO we should batch these allocations together
    with await allocator.malloc(addrlen) as addr_ptr:
        with await allocator.malloc(addrlen_buflen) as addrlen_ptr:
            # uggghh, the socket api requires a write before, a syscall, and a read after - so much overhead!
            # whyyy doesn't it just return the possible read length as an integer?
            await gateway.memcpy(addrlen_ptr, base.to_local_pointer(ffi.buffer(local_addrlen_buf)), addrlen_buflen)
            await raw_syscall_func(sysif, sockfd, addr_ptr, addrlen_ptr)
            # TODO theoretically we should copy the addrlen_buf first,
            # then only copy that much out of the addr_ptr.
            await gateway.batch_memcpy([
                (base.to_local_pointer(ffi.buffer(local_addr_buf)), addr_ptr, addrlen),
                (base.to_local_pointer(ffi.buffer(local_addrlen_buf)), addrlen_ptr, addrlen_buflen),
            ])
    ret = bytes(ffi.buffer(local_addr_buf, local_addrlen_buf[0]))
    return ret

async def getsockname(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                      sockfd: base.FileDescriptor, addrlen: int) -> bytes:
    return (await getname_helper("getsockname", raw_syscall.getsockname, sysif, gateway, allocator, sockfd, addrlen))

async def getpeername(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                      sockfd: base.FileDescriptor, addrlen: int) -> bytes:
    return (await getname_helper("getpeername", raw_syscall.getpeername, sysif, gateway, allocator, sockfd, addrlen))

async def getsockopt(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                     sockfd: base.FileDescriptor, level: int, optname: int, optlen: int) -> bytes:
    logger.debug("getsockopt(%s, %s, %s, %s)", sockfd, level, optname, optlen)
    local_opt_buf = ffi.new('char[]', optlen)
    local_optlen_buf = ffi.new('size_t*', optlen)
    optlen_buflen = ffi.sizeof(local_optlen_buf)
    with await allocator.malloc(optlen) as opt_ptr:
        with await allocator.malloc(optlen_buflen) as optlen_ptr:
            await gateway.memcpy(optlen_ptr, base.to_local_pointer(ffi.buffer(local_optlen_buf)), optlen_buflen)
            await raw_syscall.getsockopt(sysif, sockfd, level, optname, opt_ptr, optlen_ptr)
            await gateway.batch_memcpy([
                (base.to_local_pointer(ffi.buffer(local_opt_buf)), opt_ptr, optlen),
                (base.to_local_pointer(ffi.buffer(local_optlen_buf)), optlen_ptr, optlen_buflen),
            ])
    ret = bytes(ffi.buffer(local_opt_buf, local_optlen_buf[0]))
    return ret

async def setsockopt(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                     sockfd: base.FileDescriptor, level: int, optname: int, optval: bytes) -> None:
    logger.debug("setsockopt(%s, %s, %s, %s)", sockfd, level, optname, optval)
    optlen = len(optval)
    with await allocator.malloc(optlen) as optname_ptr:
        await gateway.memcpy(optname_ptr, base.to_local_pointer(optval), optlen)
        await raw_syscall.setsockopt(sysif, sockfd, level, optname, optname_ptr, optlen)

@contextlib.asynccontextmanager
async def localize_path(
        gateway: MemoryGateway, allocator: memory.Allocator, path: base.Path
) -> t.AsyncGenerator[t.Tuple[t.Optional[base.FileDescriptor], base.Pointer], None]:
    if isinstance(path.base, base.RootPathBase):
        # pathname has to be null terminated
        pathname = b"/" + path.data + b"\0"
    else:
        pathname = path.data + b"\0"
    pathname_len = len(pathname)
    with await allocator.malloc(pathname_len) as pathname_ptr:
        await gateway.memcpy(pathname_ptr, base.to_local_pointer(pathname), pathname_len)
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
                    path: base.Path, flags: int, mode: int) -> int:
    # TODO
    # logger.debug("faccessat(%s, %s, %s)", path, flags, mode)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        return (await raw_syscall.faccessat(sysif, dirfd, pathname, flags, mode))

async def mkdirat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                  path: base.Path, mode: int) -> int:
    logger.debug("mkdirat(%s, %s)", path, mode)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        return (await raw_syscall.mkdirat(sysif, dirfd, pathname, mode))

async def unlinkat(sysif: SyscallInterface, gateway: MemoryGateway, allocator: memory.Allocator,
                   path: base.Path, flags: int) -> int:
    logger.debug("unlinkat(%s, %s)", path, flags)
    async with localize_path(gateway, allocator, path) as (dirfd, pathname):
        return (await raw_syscall.unlinkat(sysif, dirfd, pathname, flags))
