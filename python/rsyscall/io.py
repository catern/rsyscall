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

import rsyscall.memory.allocator as memory
from rsyscall.memory.ram import RAM, RAMThread
from rsyscall.memory.socket_transport import SocketMemoryTransport
from rsyscall.epoller import EpollCenter, AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.loader import Trampoline, ProcessResources
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.tasks.fork import spawn_rsyscall_thread, RsyscallConnection, SyscallResponse
from rsyscall.tasks.common import raise_if_error, log_syscall
from rsyscall.command import Command
from rsyscall.environ import Environment

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
from rsyscall.network.connection import Connection, ConnectionThread

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
        try:
            return SockaddrUn(os.fsencode(self.handle))
        except PathTooLongError:
            fd = await self.thr.task.open(await self.parent.to_pointer(), O.PATH|O.CLOEXEC)
            return SockaddrUnProcFd(fd, self.name)

    # to_bytes and from_bytes, kinda sketchy, hmm....
    # from_bytes will fail at runtime... whatever

    T = t.TypeVar('T', bound='Path')
    def __truediv__(self: T, key: t.Union[str, bytes, pathlib.PurePath]) -> T:
        if isinstance(key, bytes):
            key = os.fsdecode(key)
        return type(self)(self.thr, self.handle/key)

    def __fspath__(self) -> str:
        return self.handle.__fspath__()

def random_string(k=8) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))

async def update_symlink(parent: Path, name: str, target: str) -> None:
    tmpname = name + ".updating." + random_string()
    tmppath = (parent/tmpname)
    await tmppath.symlink(target)
    await (parent/name).rename(tmppath)

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

class StandardTask(ConnectionThread):
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 connection: Connection,
                 process_resources: ProcessResources,
                 epoller: EpollCenter,
                 child_monitor: ChildProcessMonitor,
                 environ: Environment,
                 stdin: handle.FileDescriptor,
                 stdout: handle.FileDescriptor,
                 stderr: handle.FileDescriptor,
    ) -> None:
        super().__init__(task, ram, epoller, connection)
        self.process = process_resources
        self.child_monitor = child_monitor
        self.environ = environ
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ramthr(self) -> RAMThread:
        return self

    async def mkdtemp(self, prefix: str="mkdtemp") -> 'TemporaryDirectory':
        parent = Path(self.ramthr, self.environ.tmpdir)
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        name = (prefix+"."+random_suffix).encode()
        await (parent/name).mkdir(mode=0o700)
        return TemporaryDirectory(self, parent, name)

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

    async def fork(self, newuser=False, newpid=False, fs=True, sighand=True) -> RsyscallThread:
        [(access_sock, remote_sock)] = await self.make_async_connections(1)
        base_task = await spawn_rsyscall_thread(
            self.ram, self.task.base,
            access_sock, remote_sock,
            self.child_monitor, self.process,
            newuser=newuser, newpid=newpid, fs=fs, sighand=sighand,
        )
        ram = RAM(base_task,
                  # We don't inherit the transport because it leads to a deadlock:
                  # If when a child task calls transport.read, it performs a syscall in the child task,
                  # then the parent task will need to call waitid to monitor the child task during the syscall,
                  # which will in turn need to also call transport.read.
                  # But the child is already using the transport and holding the lock,
                  # so the parent will block forever on taking the lock,
                  # and child's read syscall will never complete.
                  self.ram.transport,
                  self.ram.allocator.inherit(base_task),
        )
        await remote_sock.invalidate()
        if newuser:
            # hack, we should really track the [ug]id ahead of this so we don't have to get it
            # we have to get the [ug]id from the parent because it will fail in the child
            uid = await self.task.base.getuid()
            gid = await self.task.base.getgid()
            await write_user_mappings(RAMThread(base_task, ram), uid, gid)
        if newpid or self.child_monitor.is_reaper:
            # if the new process is pid 1, then CLONE_PARENT isn't allowed so we can't use inherit_to_child.
            # if we are a reaper, than we don't want our child CLONE_PARENTing to us, so we can't use inherit_to_child.
            # in both cases we just fall back to making a new ChildProcessMonitor for the child.
            epoller = await EpollCenter.make_root(ram, base_task)
            # this signal is already blocked, we inherited the block, um... I guess...
            # TODO handle this more formally
            signal_block = SignalBlock(base_task, await ram.to_pointer(Sigset({signal.SIGCHLD})))
            child_monitor = await ChildProcessMonitor.make(ram, base_task,
                                                           epoller, signal_block=signal_block, is_reaper=newpid)
        else:
            epoller = self.epoller.inherit(ram)
            child_monitor = self.child_monitor.inherit_to_child(base_task)
        return RsyscallThread(
            base_task, ram,
            self.connection.for_task(base_task, ram),
            self.process,
            epoller, child_monitor,
            self.environ.inherit(base_task, ram),
            stdin=self.stdin.for_task(base_task),
            stdout=self.stdout.for_task(base_task),
            stderr=self.stderr.for_task(base_task),
            parent_monitor=self.child_monitor,
        )

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

class TemporaryDirectory:
    path: Path
    def __init__(self, stdtask: StandardTask, parent: Path, name: bytes) -> None:
        self.stdtask = stdtask
        self.parent = parent
        self.name = name
        self.path = parent/name

    async def cleanup(self) -> None:
        # TODO would be nice if not sharing the fs information gave us a cap to chdir
        cleanup_thread = await self.stdtask.fork(fs=False)
        async with cleanup_thread:
            await cleanup_thread.stdtask.task.base.chdir(await self.parent.to_pointer())
            name = os.fsdecode(self.name)
            child = await cleanup_thread.exec(self.stdtask.environ.sh.args(
                '-c', f"chmod -R +w -- {name} && rm -rf -- {name}"))
            await child.check()

    async def __aenter__(self) -> 'Path':
        return self.path

    async def __aexit__(self, *args, **kwargs):
        await self.cleanup()

class RsyscallInterface(near.SyscallInterface):
    """An rsyscall connection to a task that is not our child.

    For correctness, we should ensure that we'll get HUP/EOF if the task has
    exited and therefore will never respond. This is most easily achieved by
    making sure that the fds keeping the other end of the RsyscallConnection
    open, are only held by one task, and so will be closed when the task
    exits. Note, though, that that requires that the task be in an unshared file
    descriptor space.

    """
    def __init__(self, rsyscall_connection: RsyscallConnection,
                 # usually the same pid that's inside the namespaces
                 identifier_process: near.Process) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.logger = logging.getLogger(f"rsyscall.RsyscallConnection.{identifier_process.id}")
        self.identifier_process = identifier_process

    def store_remote_side_handles(self, infd: handle.FileDescriptor, outfd: handle.FileDescriptor) -> None:
        self.infd = infd
        self.outfd = outfd

    def get_activity_fd(self) -> handle.FileDescriptor:
        return self.infd

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        conn_response = await self.rsyscall_connection.write_request(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        response = SyscallResponse(self.rsyscall_connection.read_pending_responses, conn_response)
        return response

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            # we must not be interrupted while reading the response - we need to return
            # the response so that our parent can deal with the state change we created.
            with trio.CancelScope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

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

class RsyscallThread(StandardTask):
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 connection: Connection,
                 process_resources: ProcessResources,
                 epoller: EpollCenter,
                 child_monitor: ChildProcessMonitor,
                 environ: Environment,
                 stdin: handle.FileDescriptor,
                 stdout: handle.FileDescriptor,
                 stderr: handle.FileDescriptor,
                 parent_monitor: ChildProcessMonitor,
    ) -> None:
        super().__init__(
            task,
            ram,
            connection,
            process_resources,
            epoller,
            child_monitor,
            environ,
            stdin,
            stdout,
            stderr,
        )
        self.parent_monitor = parent_monitor

    @property
    def stdtask(self) -> StandardTask:
        return self

    async def exec(self, command: Command,
                   inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> AsyncChildProcess:
        return (await self.execve(command.executable_path, command.arguments, command.env_updates,
                                  inherited_signal_blocks=inherited_signal_blocks))

    async def execveat(self, path: handle.Path,
                       argv: t.List[bytes], envp: t.List[bytes], flags: AT) -> AsyncChildProcess:
        def op(sem: batch.BatchSemantics) -> t.Tuple[handle.WrittenPointer[handle.Path],
                                                     handle.WrittenPointer[handle.ArgList],
                                                     handle.WrittenPointer[handle.ArgList]]:
            argv_ptrs = handle.ArgList([sem.to_pointer(handle.Arg(arg)) for arg in argv])
            envp_ptrs = handle.ArgList([sem.to_pointer(handle.Arg(arg)) for arg in envp])
            return (sem.to_pointer(path),
                    sem.to_pointer(argv_ptrs),
                    sem.to_pointer(envp_ptrs))
        filename, argv_ptr, envp_ptr = await self.stdtask.ram.perform_batch(op)
        child_process = await self.stdtask.task.base.execve(filename, argv_ptr, envp_ptr, flags)
        return self.parent_monitor.internal.add_task(child_process)

    async def execve(self, path: handle.Path, argv: t.Sequence[t.Union[str, bytes, os.PathLike]],
                     env_updates: t.Mapping[str, t.Union[str, bytes, os.PathLike]]={},
                     inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> AsyncChildProcess:
        """Replace the running executable in this thread with another.

        We take inherited_signal_blocks as an argument so that we can default it
        to "inheriting" an empty signal mask. Most programs expect the signal
        mask to be cleared on startup. Since we're using signalfd as our signal
        handling method, we need to block signals with the signal mask; and if
        those blocked signals were inherited across exec, other programs would
        break (SIGCHLD is the most obvious example).

        We could depend on the user clearing the signal mask before calling
        exec, similar to how we require the user to remove CLOEXEC from
        inherited fds; but that is a fairly novel requirement to most, so for
        simplicity we just default to clearing the signal mask before exec, and
        allow the user to explicitly pass down additional signal blocks.

        """
        sigmask: t.Set[signal.Signals] = set()
        for block in inherited_signal_blocks:
            sigmask = sigmask.union(block.mask)
        await self.stdtask.task.base.sigprocmask((HowSIG.SETMASK, await self.stdtask.ram.to_pointer(Sigset(sigmask))))
        envp: t.Dict[bytes, bytes] = {**self.stdtask.environ.data}
        for key in env_updates:
            envp[os.fsencode(key)] = os.fsencode(env_updates[key])
        raw_envp: t.List[bytes] = []
        for key_bytes, value in envp.items():
            raw_envp.append(b''.join([key_bytes, b'=', value]))
        logger.info("execveat(%s, %s, %s)", path, argv, env_updates)
        return await self.execveat(path, [os.fsencode(arg) for arg in argv], raw_envp, AT.NONE)

    async def run(self, command: Command, check=True, *, task_status=trio.TASK_STATUS_IGNORED) -> ChildEvent:
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
