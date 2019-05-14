from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import types
import time
import traceback
import pathlib

import math


import rsyscall.handle as handle
import rsyscall.handle
from rsyscall.handle import T_pointer, Stack, WrittenPointer, MemoryMapping, Arg, ThreadProcess, MemoryGateway, Pointer, Task
import rsyscall.far as far
import rsyscall.near as near
from rsyscall.struct import T_struct, T_fixed_size, Bytes, Int32, Serializer, Struct
import rsyscall.batch as batch
from rsyscall.batch import BatchSemantics
from rsyscall.mktemp import mkdtemp, TemporaryDirectory

import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM, RAMThread
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.loader import Trampoline, NativeLoader
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.command import Command
from rsyscall.environ import Environment
from rsyscall.network.connection import Connection
from rsyscall.tasks.fork import ForkThread
from rsyscall.unix_thread import UnixThread, ChildUnixThread

from rsyscall.sys.socket import AF, SOCK, SOL, SO, Address, GenericSockaddr, SendmsgFlags, RecvmsgFlags, Sockbuf
from rsyscall.fcntl import AT, O, F, FD_CLOEXEC
from rsyscall.sys.socket import T_addr
from rsyscall.sys.mount import MS
from rsyscall.sys.un import SockaddrUn, PathTooLongError, SockaddrUnProcFd
from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.sys.epoll import EpollEvent, EpollEventList, EPOLL, EPOLL_CTL, EpollFlag
from rsyscall.sys.wait import W, ChildEvent
from rsyscall.sys.memfd import MFD
from rsyscall.sys.signalfd import SFD, SignalfdSiginfo
from rsyscall.sys.inotify import InotifyFlag
from rsyscall.sys.mman import PROT, MAP
from rsyscall.sched import UnshareFlag, CLONE
from rsyscall.signal import HowSIG, Sigaction, Sighandler, Signals, Sigset, Siginfo
from rsyscall.signal import SignalBlock
from rsyscall.linux.dirent import Dirent, DirentList
from rsyscall.unistd import SEEK

import random
import string
import abc
import prctl
import socket
import abc
import sys
import os
import typing as t
import struct
import array
import trio
import signal
from dataclasses import dataclass, field
import logging
import fcntl
import errno
import enum
import contextlib
import inspect
logger = logging.getLogger(__name__)

T = t.TypeVar('T')
class MemFileDescriptor:
    "A file descriptor, plus a task to access it from, plus the file object underlying the descriptor."
    def __init__(self, ram: RAM, handle: handle.FileDescriptor) -> None:
        self.ram = ram
        self.handle = handle

    def __str__(self) -> str:
        return f'FD({self.ram}, {self.handle})'

    async def read(self, count: int=4096) -> bytes:
        valid, _ = await self.handle.read(await self.ram.malloc_type(Bytes, count))
        return await valid.read()

    async def write(self, data: bytes) -> int:
        written, _ = await self.handle.write(await self.ram.to_pointer(Bytes(data)))
        return written.bytesize()

    async def write_all(self, data: bytes) -> None:
        remaining: handle.Pointer = await self.ram.to_pointer(Bytes(data))
        while remaining.bytesize() > 0:
            written, remaining = await self.handle.write(remaining)

    async def getdents(self, count: int=4096) -> DirentList:
        valid, _ = await self.handle.getdents(await self.ram.malloc_type(DirentList, count))
        return await valid.read()

    async def bind(self, addr: Address) -> None:
        await self.handle.bind(await self.ram.to_pointer(addr))

    async def connect(self, addr: Address) -> None:
        await self.handle.connect(await self.ram.to_pointer(addr))

    async def listen(self, backlog: int) -> None:
        await self.handle.listen(backlog)

    async def setsockopt(self, level: int, optname: int, optval: t.Union[bytes, int]) -> None:
        if isinstance(optval, bytes):
            ptr: handle.Pointer = await self.ram.to_pointer(Bytes(optval))
        else:
            ptr = await self.ram.to_pointer(Int32(optval))
        await self.handle.setsockopt(level, optname, ptr)

    async def getsockname(self) -> Address:
        written_sockbuf = await self.ram.to_pointer(Sockbuf(await self.ram.malloc_struct(GenericSockaddr)))
        sockbuf = await self.handle.getsockname(written_sockbuf)
        return (await (await sockbuf.read()).buf.read()).parse()

    async def getpeername(self) -> Address:
        written_sockbuf = await self.ram.to_pointer(Sockbuf(await self.ram.malloc_struct(GenericSockaddr)))
        sockbuf = await self.handle.getpeername(written_sockbuf)
        return (await (await sockbuf.read()).buf.read()).parse()

    async def getsockopt(self, level: int, optname: int, optlen: int) -> bytes:
        written_sockbuf = await self.ram.to_pointer(Sockbuf(await self.ram.malloc_type(Bytes, optlen)))
        sockbuf = await self.handle.getsockopt(level, optname, written_sockbuf)
        return (await (await sockbuf.read()).buf.read())

    async def accept(self, flags: SOCK) -> t.Tuple[MemFileDescriptor, Address]:
        written_sockbuf = await self.ram.to_pointer(Sockbuf(await self.ram.malloc_struct(GenericSockaddr)))
        fd, sockbuf = await self.handle.accept(flags, written_sockbuf)
        addr = (await (await sockbuf.read()).buf.read()).parse()
        return MemFileDescriptor(self.ram, fd), addr

class Path(rsyscall.path.PathLike):
    "This is a convenient combination of a Path and a Task to perform serialization."
    def __init__(self, thr: RAMThread, handle: rsyscall.path.Path) -> None:
        self.thr = thr
        self.handle = handle
        # we cache the pointer to the serialized path
        self._ptr: t.Optional[rsyscall.handle.WrittenPointer[rsyscall.path.Path]] = None

    def with_thread(self, thr: RAMThread) -> Path:
        return Path(thr, self.handle)

    @property
    def parent(self) -> Path:
        return Path(self.thr, self.handle.parent)

    @property
    def name(self) -> str:
        return self.handle.name

    async def to_pointer(self) -> rsyscall.handle.WrittenPointer[rsyscall.path.Path]:
        if self._ptr is None:
            self._ptr = await self.thr.ram.to_pointer(self.handle)
        return self._ptr

    async def mkdir(self, mode=0o777) -> Path:
        try:
            await self.thr.task.mkdir(await self.to_pointer(), mode)
        except FileExistsError as e:
            raise FileExistsError(e.errno, e.strerror, self) from None
        return self

    async def open(self, flags: O, mode=0o644) -> MemFileDescriptor:
        """Open a path

        Note that this can block forever if we're opening a FIFO

        """
        fd = await self.thr.task.open(await self.to_pointer(), flags, mode)
        return MemFileDescriptor(self.thr.ram, fd)

    async def open_directory(self) -> MemFileDescriptor:
        return (await self.open(O.DIRECTORY))

    async def open_path(self) -> MemFileDescriptor:
        return (await self.open(O.PATH))

    async def creat(self, mode=0o644) -> MemFileDescriptor:
        return await self.open(O.WRONLY|O.CREAT|O.TRUNC, mode)

    async def access(self, *, read=False, write=False, execute=False) -> bool:
        mode = 0
        if read:
            mode |= os.R_OK
        if write:
            mode |= os.W_OK
        if execute:
            mode |= os.X_OK
        # default to os.F_OK
        if mode == 0:
            mode = os.F_OK
        ptr = await self.to_pointer()
        try:
            await self.thr.task.access(ptr, mode)
            return True
        except OSError:
            return False

    async def unlink(self, flags: int=0) -> None:
        await self.thr.task.unlink(await self.to_pointer())

    async def rmdir(self) -> None:
        await self.thr.task.rmdir(await self.to_pointer())

    async def link(self, oldpath: Path, flags: int=0) -> Path:
        "Create a hardlink at Path 'self' to the file at Path 'oldpath'"
        await self.thr.task.link(await oldpath.to_pointer(), await self.to_pointer())
        return self

    async def symlink(self, target: t.Union[bytes, str, Path]) -> Path:
        "Create a symlink at Path 'self' pointing to the passed-in target"
        if isinstance(target, Path):
            target_ptr = await target.to_pointer()
        else:
            # TODO should write the bytes directly, rather than going through Path;
            # Path will canonicalize the bytes as a path, which isn't right
            target_ptr = await self.thr.ram.to_pointer(handle.Path(os.fsdecode(target)))
        await self.thr.task.symlink(target_ptr, await self.to_pointer())
        return self

    async def rename(self, oldpath: Path, flags: int=0) -> Path:
        "Create a file at Path 'self' by renaming the file at Path 'oldpath'"
        await self.thr.task.rename(await oldpath.to_pointer(), await self.to_pointer())
        return self

    async def readlink(self) -> Path:
        size = 4096
        valid, _ = await self.thr.task.readlink(await self.to_pointer(),
                                                 await self.thr.ram.malloc_type(rsyscall.path.Path, size))
        if valid.bytesize() == size:
            # ext4 limits symlinks to this size, so let's just throw if it's larger;
            # we can add retry logic later if we ever need it
            raise Exception("symlink longer than 4096 bytes, giving up on readlinking it")
        # readlink doesn't append a null byte, so unfortunately we can't save this buffer and use it for later calls
        return Path(self.thr, await valid.read())

    async def canonicalize(self) -> Path:
        f = await self.open_path()
        ret = await Path(self.thr, f.handle.as_proc_path()).readlink()
        await f.handle.close()
        return ret

    async def as_sockaddr_un(self) -> SockaddrUn:
        """Turn this path into a SockaddrUn, hacking around the 108 byte limit on socket addresses.

        If the passed path is too long to fit in an address, this function will open the parent
        directory with O_PATH and return SockaddrUn("/proc/self/fd/n/name").

        """
        return await SockaddrUn.from_path(self.thr.task, self.thr.ram, self.handle)

    # to_bytes and from_bytes, kinda sketchy, hmm....
    # from_bytes will fail at runtime... whatever

    T = t.TypeVar('T', bound='Path')
    def __truediv__(self: T, key: t.Union[str, bytes, pathlib.PurePath]) -> T:
        if isinstance(key, bytes):
            key = os.fsdecode(key)
        return type(self)(self.thr, self.handle/key)

    def __fspath__(self) -> str:
        return self.handle.__fspath__()

async def write_user_mappings(thr: RAMThread, uid: int, gid: int,
                              in_namespace_uid: int=None, in_namespace_gid: int=None) -> None:
    if in_namespace_uid is None:
        in_namespace_uid = uid
    if in_namespace_gid is None:
        in_namespace_gid = gid
    procself = handle.Path("/proc/self")

    uid_map = await thr.task.open(await thr.ram.to_pointer(procself/"uid_map"), O.WRONLY)
    await uid_map.write(await thr.ram.to_pointer(Bytes(f"{in_namespace_uid} {uid} 1\n".encode())))
    await uid_map.close()

    setgroups = await thr.task.open(await thr.ram.to_pointer(procself/"setgroups"), O.WRONLY)
    await setgroups.write(await thr.ram.to_pointer(Bytes(b"deny")))
    await setgroups.close()

    gid_map = await thr.task.open(await thr.ram.to_pointer(procself/"gid_map"), O.WRONLY)
    await gid_map.write(await thr.ram.to_pointer(Bytes(f"{in_namespace_gid} {gid} 1\n".encode())))
    await gid_map.close()

class Thread(UnixThread):
    @property
    def ramthr(self) -> RAMThread:
        return self

    async def mkdtemp(self, prefix: str="mkdtemp") -> TemporaryDirectory:
        return await mkdtemp(self, prefix)

    async def spit(self, path: handle.Path, text: t.Union[str, bytes], mode=0o644) -> handle.Path:
        """Open a file, creating and truncating it, and write the passed text to it

        Probably shouldn't use this on FIFOs or anything.

        Returns the passed-in Path so this serves as a nice pseudo-constructor.

        """
        fd = await self.task.base.open(await self.ram.to_pointer(path), O.WRONLY|O.TRUNC|O.CREAT, mode=mode)
        to_write: Pointer = await self.ram.to_pointer(Bytes(os.fsencode(text)))
        while to_write.bytesize() > 0:
            _, to_write = await fd.write(to_write)
        await fd.close()
        return path

    async def mount(self, source: bytes, target: bytes,
                    filesystemtype: bytes, mountflags: MS,
                    data: bytes) -> None:
        def op(sem: batch.BatchSemantics) -> t.Tuple[
                WrittenPointer[Arg], WrittenPointer[Arg], WrittenPointer[Arg], WrittenPointer[Arg]]:
            return (
                sem.to_pointer(Arg(source)),
                sem.to_pointer(Arg(target)),
                sem.to_pointer(Arg(filesystemtype)),
                sem.to_pointer(Arg(data)),
            )
        source_ptr, target_ptr, filesystemtype_ptr, data_ptr = await self.ram.perform_batch(op)
        await self.task.base.mount(source_ptr, target_ptr, filesystemtype_ptr, mountflags, data_ptr)

    async def fork(self, newuser=False, newpid=False, fs=True, sighand=True) -> ChildThread:
        thread = await super().fork(newuser=newuser, newpid=newpid, fs=fs, sighand=sighand)
        if newuser:
            # hack, we should really track the [ug]id ahead of this so we don't have to get it
            # we have to get the [ug]id from the parent because it will fail in the child
            uid = await self.task.getuid()
            gid = await self.task.getgid()
            await write_user_mappings(thread, uid, gid)
        return ChildThread(thread, thread.parent_monitor)

    async def run(self, command: Command, check=True,
                  *, task_status=trio.TASK_STATUS_IGNORED) -> ChildEvent:
        thread = await self.fork(fs=False)
        child = await thread.exec(command)
        task_status.started(child)
        exit_event = await child.wait_for_exit()
        if check:
            exit_event.check()
        return exit_event

    async def unshare_files(self, going_to_exec=True) -> None:
        """Unshare the file descriptor table.

        Set going_to_exec to False if you are going to keep this task around long-term, and we'll do
        a manual cloexec in userspace to clear out fds held by any other non-rsyscall libraries,
        which are automatically copied by Linux into the new fd space.

        We default going_to_exec to True because there's little reason to call unshare_files other
        than to then exec; and even if you do want to call unshare_files without execing, there
        probably aren't any significant other libraries in the FD space; and even if there are such
        libraries, it usually doesn't matter to keep stray references around to their FDs.

        TODO maybe this should return an object that lets us unset CLOEXEC on things?

        """
        await self.task.base.unshare_files()
        if not going_to_exec:
            await do_cloexec_except(self.ramthr, set([fd.near for fd in self.task.base.fd_handles]))

    async def unshare_files_and_replace(self, mapping: t.Dict[handle.FileDescriptor, handle.FileDescriptor],
                                        going_to_exec=False) -> None:
        mapping = {
            # we maybe_copy the key because we need to have the only handle to it in the task,
            # which we'll then consume through dup3.
            key.maybe_copy(self.task.base):
            # we for_task the value so that we get a copy of it, which we then explicitly invalidate;
            # this means if we had the only reference to the fd passed into us as an expression,
            # we will close that fd - nice.
            val.for_task(self.task.base)
            for key, val in mapping.items()}
        await self.unshare_files(going_to_exec=going_to_exec)
        for dest, source in mapping.items():
            await source.dup3(dest, 0)
            await source.invalidate()

    async def unshare_user(self,
                           in_namespace_uid: int=None, in_namespace_gid: int=None) -> None:
        uid = await self.task.base.getuid()
        gid = await self.task.base.getgid()
        await self.task.base.unshare_user()
        await write_user_mappings(self.ramthr, uid, gid,
                                  in_namespace_uid=in_namespace_uid, in_namespace_gid=in_namespace_gid)

    async def unshare_net(self) -> None:
        await self.task.base.unshare_net()

    async def setns_user(self, fd: handle.FileDescriptor) -> None:
        await self.task.base.setns_user(fd)

    async def unshare_mount(self) -> None:
        await rsyscall.near.unshare(self.task.base.sysif, UnshareFlag.NEWNS)

    async def setns_mount(self, fd: handle.FileDescriptor) -> None:
        fd.check_is_for(self.task.base)
        await fd.setns(UnshareFlag.NEWNS)

    async def exit(self, status) -> None:
        await self.task.base.exit(0)

    async def close(self) -> None:
        await self.task.base.close_task()

    async def __aenter__(self) -> 'StandardTask':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()
StandardTask = Thread

async def do_cloexec_except(thr: RAMThread, excluded_fds: t.Set[near.FileDescriptor]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    buf = await thr.ram.malloc_type(DirentList, 4096)
    dirfd = await thr.task.open(await thr.ram.to_pointer(handle.Path("/proc/self/fd")), O.DIRECTORY|O.CLOEXEC)
    async def maybe_close(fd: near.FileDescriptor) -> None:
        flags = await near.fcntl(thr.task.sysif, fd, F.GETFD)
        if (flags & FD_CLOEXEC) and (fd not in excluded_fds):
            await near.close(thr.task.sysif, fd)
    async with trio.open_nursery() as nursery:
        while True:
            valid, rest = await dirfd.getdents(buf)
            if valid.bytesize() == 0:
                break
            dents = await valid.read()
            for dent in dents:
                try:
                    num = int(dent.name)
                except ValueError:
                    continue
                nursery.start_soon(maybe_close, near.FileDescriptor(num))
            buf = valid.merge(rest)

class ChildThread(StandardTask, ChildUnixThread):
    @property
    def stdtask(self) -> StandardTask:
        return self

    async def exec_run(self, command: Command, check=True, *, task_status=trio.TASK_STATUS_IGNORED) -> ChildEvent:
        child = await self.exec(command)
        task_status.started(child)
        exit_event = await child.wait_for_exit()
        if check:
            exit_event.check()
        return exit_event

    async def close(self) -> None:
        await self.stdtask.task.base.close_task()

    async def __aenter__(self) -> StandardTask:
        return self.stdtask

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()

RsyscallThread = ChildThread

async def exec_cat(thread: RsyscallThread, cat: Command,
                   stdin: handle.FileDescriptor, stdout: handle.FileDescriptor) -> AsyncChildProcess:
    await thread.stdtask.unshare_files_and_replace({
        thread.stdtask.stdin: stdin,
        thread.stdtask.stdout: stdout,
    }, going_to_exec=True)
    child_task = await thread.exec(cat)
    return child_task

async def read_all(fd: MemFileDescriptor) -> bytes:
    buf = b""
    while True:
        data = await fd.read()
        if len(data) == 0:
            return buf
        buf += data

async def read_full(read: t.Callable[[int], t.Awaitable[bytes]], size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        buf += await read(size - len(buf))
    return buf
