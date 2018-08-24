from rsyscall.base import SyscallInterface, Task, FileDescriptor, Pointer

# TODO verify that pointers and file descriptors come from the same
# address space and fd namespace as the task.
async def pipe(task: Task, buf: Pointer, flags: int) -> None:
    logger.debug("pipe(%s, %s)", buf, flags)
    await task.sysif.syscall(lib.SYS_pipe2, buf, flags)

async def close(task: Task, fd: FileDescriptor) -> None:
    logger.debug("close(%s)", fd)
    await task.sysif.syscall(lib.SYS_close, fd)

async def read(task: Task, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("read(%s, %s, %d)", fd, buf, count)
    return (await task.sysif.syscall(lib.SYS_read, fd, buf, count))

async def write(task: Task, fd: FileDescriptor, buf: Pointer, count: int) -> int:
    logger.debug("write(%s, %s, %d)", fd, buf, count)
    return (await task.sysif.syscall(lib.SYS_write, fd, buf, count))

async def dup2(task: Task, oldfd: FileDescriptor, newfd: FileDescriptor) -> None:
    logger.debug("dup2(%s, %s)", oldfd, newfd)
    await task.sysif.syscall(lib.SYS_dup2, oldfd, newfd)

async def clone(task: Task, flags: int, child_stack: Pointer,
                ptid: Pointer, ctid: Pointer,
                newtls: Pointer) -> int:
    logger.debug("clone(%s, %s, %s, %s, %s)", flags, child_stack, ptid, ctid, newtls)
    return (await task.sysif.syscall(lib.SYS_clone, flags, child_stack, ptid, ctid, newtls))

async def exit(task: Task, status: int) -> None:
    logger.debug("exit(%d)", status)
    try:
        await task.sysif.syscall(lib.SYS_exit, status)
    except RsyscallHangup:
        # a hangup means the exit was successful
        pass

async def execveat(sysif: SyscallInterface, dirfd: FileDescriptor, path: Pointer,
                   argv: Pointer, envp: Pointer, flags: int) -> None:
    logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
    try:
        await self.syscall(lib.SYS_execveat, dirfd, path, argv, envp, flags)
    except RsyscallHangup:
        # a hangup means the exec was successful. other exceptions will propagate through
        pass

async def execveat(self, dirfd: int, path: bytes,
                   argv: t.List[bytes], envp: t.List[bytes],
                   flags: int) -> None:
    logger.debug("execveat(%s, %s, %s, %s)", dirfd, path, argv, flags)
    # this null-terminated-array logic is tricky to extract out into a separate function due to lifetime issues
    null_terminated_args = [ffi.new('char[]', arg) for arg in argv]
    argv_bytes = ffi.new('char *const[]', null_terminated_args + [ffi.NULL])
    null_terminated_env_vars = [ffi.new('char[]', arg) for arg in envp]
    envp_bytes = ffi.new('char *const[]', null_terminated_env_vars + [ffi.NULL])
    path_bytes = ffi.new('char[]', path)
    try:
        await self.syscall(lib.SYS_execveat, dirfd, path_bytes, argv_bytes, envp_bytes, flags)
    except RsyscallHangup:
        # a hangup means the exec was successful. other exceptions will propagate through
        pass

async def mmap(self, addr: int, length: int, prot: int, flags: int, fd: int, offset: int) -> int:
    logger.debug("mmap(%s, %s, %s, %s, %s, %s)", addr, length, prot, flags, fd, offset)
    return (await self.syscall(lib.SYS_mmap, addr, length, prot, flags, fd, offset))

async def munmap(self, addr: int, length: int) -> None:
    logger.debug("munmap(%s, %s)", addr, length)
    await self.syscall(lib.SYS_munmap, addr, length)

async def exit_group(self, status: int) -> None:
    logger.debug("exit_group(%d)", status)
    await self.syscall(lib.SYS_exit_group, status)

async def getpid(self) -> int:
    logger.debug("getpid()")
    return (await self.syscall(lib.SYS_getpid))

async def epoll_create(self, flags: int) -> int:
    logger.debug("epoll_create(%s)", flags)
    return (await self.syscall(lib.SYS_epoll_create1, flags))

async def epoll_ctl_add(self, epfd: int, fd: int, event: EpollEvent) -> None:
    logger.debug("epoll_ctl_add(%d, %d, %s)", epfd, fd, event)
    await self.syscall(lib.SYS_epoll_ctl, epfd, lib.EPOLL_CTL_ADD, fd, event.to_bytes())

async def epoll_ctl_mod(self, epfd: int, fd: int, event: EpollEvent) -> None:
    logger.debug("epoll_ctl_mod(%d, %d, %s)", epfd, fd, event)
    await self.syscall(lib.SYS_epoll_ctl, epfd, lib.EPOLL_CTL_MOD, fd, event.to_bytes())

async def epoll_ctl_del(self, epfd: int, fd: int) -> None:
    logger.debug("epoll_ctl_del(%d, %d)", epfd, fd)
    await self.syscall(lib.SYS_epoll_ctl, epfd, lib.EPOLL_CTL_DEL, fd)

async def epoll_wait(self, epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]:
    logger.debug("epoll_wait(%d, maxevents=%d, timeout=%d)", epfd, maxevents, timeout)
    c_events = ffi.new('struct epoll_event[]', maxevents)
    count = await self.syscall(lib.SYS_epoll_wait, epfd, c_events, maxevents, timeout)
    ret = []
    for ev in c_events[0:count]:
        ret.append(EpollEvent(ev.data.u64, EpollEventMask(ev.events)))
    return ret

@t.overload
async def fcntl(self, fd: int, cmd: int, arg: int=0) -> int: ...
@t.overload
async def fcntl(self, fd: int, cmd: int, arg: bytes) -> bytes:
    "This follows the same protocol as fcntl.fcntl."
    ...
async def fcntl(self, fd: int, cmd: int, arg=0) -> t.Union[bytes, int]:
    "This follows the same protocol as fcntl.fcntl."
    logger.debug("fcntl(%d, %d, %s)", fd, cmd, arg)
    if isinstance(arg, int):
        return (await self.syscall(lib.SYS_fcntl, fd, cmd, arg))
    elif isinstance(arg, bytes):
        raise NotImplementedError
    else:
        raise Exception

async def prctl_set_child_subreaper(self, flag: bool) -> None:
    logger.debug("prctl_set_child_subreaper(%s)", flag)
    # TODO also this guy
    raise NotImplementedError

async def faccessat(self, dirfd: int, pathname: bytes, mode: int, flags: int) -> None:
    logger.debug("faccessat(%s, %s, %s)", dirfd, pathname, mode)
    await self.syscall(lib.SYS_faccessat, dirfd, null_terminated(pathname), mode, flags)

async def chdir(self, path: bytes) -> None:
    logger.debug("chdir(%s)", path)
    await self.syscall(lib.SYS_chdir, null_terminated(path))

async def fchdir(self, fd: int) -> None:
    logger.debug("fchdir(%s)", fd)
    await self.syscall(lib.SYS_fchdir, fd)

async def mkdirat(self, dirfd: int, pathname: bytes, mode: int) -> None:
    logger.debug("mkdirat(%s, %s, %s)", dirfd, pathname, mode)
    await self.syscall(lib.SYS_mkdirat, dirfd, null_terminated(pathname), mode)

async def openat(self, dirfd: int, pathname: bytes, flags: int, mode: int) -> int:
    logger.debug("openat(%s, %s, %s, %s)", dirfd, pathname, flags, mode)
    ret = await self.syscall(lib.SYS_openat, dirfd, null_terminated(pathname), flags, mode)
    return ret

async def getdents(self, fd: int, count: int) -> t.List[Dirent]:
    logger.debug("getdents64(%s, %s)", fd, count)
    buf = ffi.new('char[]', count)
    ret = await self.syscall(lib.SYS_getdents64, fd, buf, count)
    return rsyscall.stat.getdents64_parse(ffi.buffer(buf, ret))

async def lseek(self, fd: int, offset: int, whence: int) -> int:
    logger.debug("lseek(%s, %s, %s)", fd, offset, whence)
    return (await self.syscall(lib.SYS_lseek, fd, offset, whence))

async def unlinkat(self, dirfd: int, pathname: bytes, flags: int) -> None:
    logger.debug("unlinkat(%s, %s, %s)", dirfd, pathname, flags)
    await self.syscall(lib.SYS_unlinkat, dirfd, null_terminated(pathname), flags)

async def linkat(self, olddirfd: int, oldpath: bytes, newdirfd: int, newpath: bytes, flags: int) -> None:
    logger.debug("linkat(%s, %s, %s, %s, %s)", olddirfd, oldpath, newdirfd, newpath, flags)
    await self.syscall(lib.SYS_linkat, olddirfd, null_terminated(oldpath), newdirfd, null_terminated(newpath), flags)

async def symlinkat(self, target: bytes, newdirfd: int, newpath: bytes) -> None:
    logger.debug("symlinkat(%s, %s, %s)", target, newdirfd, newpath)
    await self.syscall(lib.SYS_symlinkat, null_terminated(target), newdirfd, newpath)

async def readlinkat(self, dirfd: int, pathname: bytes, bufsiz: int) -> bytes:
    logger.debug("readlinkat(%s, %s, %s)", dirfd, pathname, bufsiz)
    buf = ffi.new('char[]', bufsiz)
    await self.syscall(lib.SYS_readlinkat, dirfd, null_terminated(pathname), bufsiz)
    return ffi.buffer(bufsiz)

async def waitid(self, idtype: IdType, id: int, options: int, *, want_child_event: bool, want_rusage: bool
) -> t.Tuple[int, t.Optional[bytes], t.Optional[bytes]]:
    logger.debug("waitid(%s, %s, %s, want_child_event=%s, want_rusage=%s)", idtype, id, options, want_child_event, want_rusage)
    if want_child_event:
        siginfo = ffi.new('siginfo_t*')
    else:
        siginfo = ffi.NULL
    if want_rusage:
        rusage = ffi.new('struct rusage*')
    else:
        rusage = ffi.NULL
    ret = await self.syscall(lib.SYS_waitid, idtype, id, siginfo, options, rusage)
    return ret, bytes(ffi.buffer(siginfo)) if siginfo else None, bytes(ffi.buffer(rusage)) if rusage else None

async def signalfd(self, fd: int, mask: t.Set[signal.Signals], flags: int) -> int:
    logger.debug("signalfd(%s, %s, %s)", fd, mask, flags)
    # sigset_t is just a 64bit bitmask of signals, I don't need the manipulation macros.
    set_integer = 0
    for sig in mask:
        set_integer |= 1 << (sig-1)
    set_data = ffi.new('unsigned long*', set_integer)
    return (await self.syscall(lib.SYS_signalfd4, fd, set_data, ffi.sizeof('unsigned long'), flags))

async def rt_sigprocmask(self, how: SigprocmaskHow, set: t.Optional[t.Set[signal.Signals]]) -> t.Set[signal.Signals]:
    logger.debug("rt_sigprocmask(%s, %s)", how, set)
    old_set = ffi.new('unsigned long*')
    if set is None:
        await self.syscall(lib.SYS_rt_sigprocmask, how, ffi.NULL, old_set, ffi.sizeof('unsigned long'))
    else:
        set_integer = 0
        for sig in set:
            set_integer |= 1 << (sig-1)
        new_set = ffi.new('unsigned long*', set_integer)
        await self.syscall(lib.SYS_rt_sigprocmask, how, new_set, old_set, ffi.sizeof('unsigned long'))
    return {signal.Signals(bit) for bit in bits(old_set[0])}

async def bind(self, sockfd: int, addr: bytes) -> None:
    logger.debug("bind(%s, %s)", sockfd, addr)
    await self.syscall(lib.SYS_bind, sockfd, ffi.from_buffer(addr), len(addr))

async def listen(self, sockfd: int, backlog: int) -> None:
    logger.debug("listen(%s, %s)", sockfd, backlog)
    await self.syscall(lib.SYS_listen, sockfd, backlog)

async def connect(self, sockfd: int, addr: bytes) -> None:
    logger.debug("connect(%s, %s)", sockfd, addr)
    await self.syscall(lib.SYS_connect, sockfd, ffi.from_buffer(addr), len(addr))

async def accept(self, sockfd: int, addrlen: int, flags: int) -> t.Tuple[int, bytes]:
    logger.debug("accept(%s, %s, %s)", sockfd, addrlen, flags)
    buf = ffi.new('char[]', addrlen)
    lenbuf = ffi.new('size_t*', addrlen)
    fd = await self.syscall(lib.SYS_accept4, sockfd, buf, lenbuf, flags)
    return fd, bytes(ffi.buffer(buf, lenbuf[0]))

async def getsockname(self, sockfd: int, addrlen: int) -> bytes:
    logger.debug("getsockname(%s, %s)", sockfd, addrlen)
    buf = ffi.new('char[]', addrlen)
    lenbuf = ffi.new('size_t*', addrlen)
    await self.syscall(lib.SYS_getsockname, sockfd, buf, lenbuf)
    return bytes(ffi.buffer(buf, lenbuf[0]))

async def getpeername(self, sockfd: int, addrlen: int) -> bytes:
    logger.debug("getpeername(%s, %s)", sockfd, addrlen)
    buf = ffi.new('char[]', addrlen)
    lenbuf = ffi.new('size_t*', addrlen)
    await self.syscall(lib.SYS_getpeername, sockfd, buf, lenbuf)
    return bytes(ffi.buffer(buf, lenbuf[0]))

async def socket(self, domain: int, type: int, protocol: int) -> int:
    logger.debug("socket(%s, %s, %s)", domain, type, protocol)
    return (await self.syscall(lib.SYS_socket, domain, type, protocol))

async def socketpair(self, domain: int, type: int, protocol: int) -> t.Tuple[int, int]:
    logger.debug("socketpair(%s, %s, %s)", domain, type, protocol)
    sv = ffi.new('int[2]')
    await self.syscall(lib.SYS_socketpair, domain, type, protocol, sv)
    return (sv[0], sv[1])

async def getsockopt(self, sockfd: int, level: int, optname: int, optlen: int) -> bytes:
    logger.debug("getsockopt(%s, %s, %s, %s)", sockfd, level, optname, optlen)
    buf = ffi.new('char[]', optlen)
    lenbuf = ffi.new('size_t*', optlen)
    # some custom netfilter socket options could return an actual value, according to getsockopt(2).
    # if that ever matters for anyone, we should change this to return a Tuple[int, bytes].
    await self.syscall(lib.SYS_getsockopt, sockfd, level, optname, buf, lenbuf)
    return bytes(ffi.buffer(buf, lenbuf[0]))

async def setsockopt(self, sockfd: int, level: int, optname: int, optval: t.Optional[bytes], *, optlen: t.Optional[int]=None) -> None:
    logger.debug("setsockopt(%s, %s, %s, %s)", sockfd, level, optname, optval)
    if optval is None:
        # AF_ALG has some stupid API where to set an option to "val", it wants you to call with
        # optval=NULL and optlen=val.  so we have to contort ourselves to make that possible.
        if optlen == None:
            raise ValueError("if optval is None, optlen must be passed")
        buf = ffi.NULL
        length = optlen
    else:
        buf = ffi.from_buffer(optval)
        length = len(optval)
    await self.syscall(lib.SYS_setsockopt, sockfd, level, optname, buf, length)

async def kill(self, pid: int, sig: signal.Signals) -> None:
    logger.debug("kill(%s, %s)", pid, sig)
    await self.syscall(lib.SYS_kill, pid, sig)

async def unshare(self, flags: UnshareFlag) -> None:
    logger.debug("unshare(%s)", flags)
    await self.syscall(lib.SYS_unshare, flags)
    
async def setns(self, fd: int, nstype: NsType) -> None:
    raise NotImplementedError
