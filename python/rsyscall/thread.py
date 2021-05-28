"Central thread class, with helper methods to ease a number of common tasks"
from __future__ import annotations
from dataclasses import dataclass
from rsyscall.command import Command
from rsyscall.environ import Environment
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.handle import FileDescriptor, WrittenPointer, Pointer, Task
from rsyscall.handle.fd import _close
from rsyscall.loader import Trampoline, NativeLoader
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.network.connection import Connection
from rsyscall.path import Path
from rsyscall.struct import FixedSize, T_fixed_size, HasSerializer, T_has_serializer, FixedSerializer, T_fixed_serializer, T_pathlike
from rsyscall.tasks.clone import clone_child_task
import logging
import os
import rsyscall.near
import rsyscall.near.types as near
import trio
import typing as t

from rsyscall.fcntl import O, F, FD, _fcntl
from rsyscall.linux.dirent import DirentList
from rsyscall.sched import CLONE
from rsyscall.signal import Sigset, SIG, SignalBlock, HowSIG
from rsyscall.sys.mount import MS
from rsyscall.sys.wait import ChildState, W
from rsyscall.sys.socket import Socketpair, AF, SOCK, T_sockaddr, Sockbuf
from rsyscall.unistd import Pipe, ArgList

logger = logging.getLogger(__name__)

async def write_user_mappings(thr: Thread, uid: int, gid: int,
                              in_namespace_uid: int=None, in_namespace_gid: int=None) -> None:
    """Set up a new user namespace with single-user {uid,gid}_map

    These are the only valid mappings for unprivileged user namespaces.
    """
    if in_namespace_uid is None:
        in_namespace_uid = uid
    if in_namespace_gid is None:
        in_namespace_gid = gid
    procself = Path("/proc/self")

    uid_map = await thr.task.open(await thr.ram.ptr(procself/"uid_map"), O.WRONLY)
    await uid_map.write(await thr.ram.ptr(f"{in_namespace_uid} {uid} 1\n".encode()))
    await uid_map.close()

    setgroups = await thr.task.open(await thr.ram.ptr(procself/"setgroups"), O.WRONLY)
    await setgroups.write(await thr.ram.ptr(b"deny"))
    await setgroups.close()

    gid_map = await thr.task.open(await thr.ram.ptr(procself/"gid_map"), O.WRONLY)
    await gid_map.write(await thr.ram.ptr(f"{in_namespace_gid} {gid} 1\n".encode()))
    await gid_map.close()

async def do_cloexec_except(thr: Thread, excluded_fds: t.Set[near.FileDescriptor]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    # it's important to do this so we can't try to inherit the fds that we close here
    thr.task.fd_table.remove_inherited()
    buf = await thr.ram.malloc(DirentList, 4096)
    dirfd = await thr.task.open(await thr.ram.ptr("/proc/self/fd"), O.DIRECTORY)
    excluded_fds.add(dirfd.near)
    async def maybe_close(fd: near.FileDescriptor) -> None:
        flags = await _fcntl(thr.task.sysif, fd, F.GETFD)
        if (flags & FD.CLOEXEC) and (fd not in excluded_fds):
            await _close(thr.task.sysif, fd)
    async with trio.open_nursery() as nursery:
        while True:
            valid, rest = await dirfd.getdents(buf)
            if valid.size() == 0:
                break
            dents = await valid.read()
            for dent in dents:
                try:
                    num = int(dent.name)
                except ValueError:
                    continue
                nursery.start_soon(maybe_close, near.FileDescriptor(num))
            buf = valid.merge(rest)
    await dirfd.close()

class Thread:
    "A central class holding everything necessary to work with some thread, along with various helpers"
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 connection: Connection,
                 loader: NativeLoader,
                 epoller: Epoller,
                 child_monitor: ChildProcessMonitor,
                 environ: Environment,
                 stdin: FileDescriptor,
                 stdout: FileDescriptor,
                 stderr: FileDescriptor,
    ) -> None:
        self.task = task
        "The `Task` associated with this process"
        self.ram = ram
        self.epoller = epoller
        self.connection = connection
        "This thread's `rsyscall.network.connection.Connection`"
        self.loader = loader
        self.monitor = child_monitor
        self.environ = environ
        "This thread's `rsyscall.environ.Environment`"
        self.stdin = stdin
        "The standard input `FileDescriptor` (FD 0)"
        self.stdout = stdout
        "The standard output `FileDescriptor` (FD 1)"
        self.stderr = stderr
        "The standard error `FileDescriptor` (FD 2)"

    def _init_from(self, thr: Thread) -> None:
        self.task = thr.task
        self.ram = thr.ram
        self.epoller = thr.epoller
        self.connection = thr.connection
        self.loader = thr.loader
        self.monitor = thr.monitor
        self.environ = thr.environ
        self.stdin = thr.stdin
        self.stdout = thr.stdout
        self.stderr = thr.stderr

    @t.overload
    async def malloc(self, cls: t.Type[T_fixed_size]) -> Pointer[T_fixed_size]:
        "malloc a fixed size type"
        pass
    @t.overload
    async def malloc(self, cls: t.Type[T_fixed_serializer], size: int) -> Pointer[T_fixed_serializer]:
        "malloc specifying a specific size"
        pass
    @t.overload
    async def malloc(self, cls: t.Type[T_pathlike], size: int) -> Pointer[T_pathlike]: ...
    @t.overload
    async def malloc(self, cls: t.Type[str], size: int) -> Pointer[str]: ...
    @t.overload
    async def malloc(self, cls: t.Type[bytes], size: int) -> Pointer[bytes]: ...

    async def malloc(self, cls: t.Type[t.Union[FixedSize, FixedSerializer, os.PathLike, str, bytes]],
                     size: int=None) -> Pointer:
        """Allocate a buffer for this type, with the specified size if required

        If `malloc` is given a `rsyscall.struct.FixedSize` type, the size must not be passed;
        if `malloc` is given any other type, the size must be passed.

        Any type which inherits from `rsyscall.struct.FixedSerializer` is supported.
        As a special case for convenience, `bytes`, `str`, and `os.PathLike` are also supported;
        `bytes` will be written out as they are, and `str` and `os.PathLike` will be null-terminated.

        """
        return await self.ram.malloc(cls, size) # type: ignore

    @t.overload
    async def ptr(self, data: T_has_serializer) -> WrittenPointer[T_has_serializer]: ...
    @t.overload
    async def ptr(self, data: T_pathlike) -> WrittenPointer[T_pathlike]: ...
    @t.overload
    async def ptr(self, data: str) -> WrittenPointer[str]: ...
    @t.overload
    async def ptr(self, data: bytes) -> WrittenPointer[bytes]: ...
    async def ptr(self, data: t.Union[HasSerializer, os.PathLike, str, bytes]) -> WrittenPointer:
        """Allocate a buffer for this data, and write the data to that buffer

        Any value which inherits from `HasSerializer` is supported.
        As a special case for convenience, `bytes`, `str`, and `os.PathLike` are also supported;
        `bytes` will be written out as they are, and `str` and `os.PathLike` will be null-terminated.
        """
        return await self.ram.ptr(data)

    async def make_afd(self, fd: FileDescriptor, set_nonblock: bool=False) -> AsyncFileDescriptor:
        """Make an AsyncFileDescriptor; make it nonblocking if `set_nonblock` is True.

        Make sure that `fd` is already in non-blocking mode;
        such as by accepting it with the `SOCK.NONBLOCK` flag;
        if it's not, you can pass set_nonblock=True to make it nonblocking.

        """
        if set_nonblock:
            await fd.fcntl(F.SETFL, O.NONBLOCK)
        return await AsyncFileDescriptor.make(self.epoller, self.ram, fd)

    async def open_async_channels(self, count: int) -> t.List[t.Tuple[AsyncFileDescriptor, FileDescriptor]]:
        "Calls self.connection.open_async_channels; see `Connection.open_async_channels`"
        return (await self.connection.open_async_channels(count))

    async def open_channels(self, count: int) -> t.List[t.Tuple[FileDescriptor, FileDescriptor]]:
        "Calls self.connection.open_channels; see `Connection.open_channels`"
        return (await self.connection.open_channels(count))

    @t.overload
    async def spit(self, path: FileDescriptor, text: t.Union[str, bytes]) -> None:
        pass

    @t.overload
    async def spit(self, path: Path, text: t.Union[str, bytes], mode=0o644) -> Path:
        pass

    async def spit(self, path: t.Union[Path, FileDescriptor], text: t.Union[str, bytes], mode=0o644) -> t.Optional[Path]:
        """Open a file, creating and truncating it, and write the passed text to it

        Probably shouldn't use this on FIFOs or anything.

        Returns the passed-in Path so this serves as a nice pseudo-constructor.

        """
        if isinstance(path, Path):
            out: t.Optional[Path] = path
            fd = await self.task.open(await self.ram.ptr(path), O.WRONLY|O.TRUNC|O.CREAT, mode=mode)
        else:
            out = None
            fd = path
        to_write: Pointer = await self.ram.ptr(os.fsencode(text))
        while to_write.size() > 0:
            _, to_write = await fd.write(to_write)
        await fd.close()
        return out

    async def bind_getsockname(self, sock: FileDescriptor, addr: T_sockaddr) -> T_sockaddr:
        """Call bind and then getsockname on `sock`.

        bind followed by getsockname is a common pattern when allocating unused
        source ports with SockaddrIn(0, ...).  Unfortunately, memory allocation
        for getsockname is quite verbose, so it would be nice to have a helper
        to make that pattern easier. Since we don't want to encourage usage of
        getsockname (it should be rarely used outside of that pattern), we add a
        helper for that specific pattern, rather than getsockname on its own.

        """
        written_addr_ptr = await self.ram.ptr(addr)
        await sock.bind(written_addr_ptr)
        sockbuf_ptr = await sock.getsockname(await self.ram.ptr(Sockbuf(written_addr_ptr)))
        addr_ptr = (await sockbuf_ptr.read()).buf
        return await addr_ptr.read()

    async def mkdir(self, path: Path, mode=0o755) -> Path:
        "Make a directory at this path"
        await self.task.mkdir(await self.ram.ptr(path))
        return path

    async def read_to_eof(self, fd: FileDescriptor) -> bytes:
        "Read this file descriptor until we get EOF, then return all the bytes read"
        data = b""
        while True:
            read, rest = await fd.read(await self.ram.malloc(bytes, 4096))
            if read.size() == 0:
                return data
            # TODO this would be more efficient if we batched our memory-reads at the end
            data += await read.read()

    async def mount(self, source: t.Union[str, os.PathLike], target: t.Union[str, os.PathLike],
                    filesystemtype: str, mountflags: MS,
                    data: str) -> None:
        "Call mount with these args"
        async def op(sem: RAM) -> t.Tuple[
                WrittenPointer[t.Union[str, os.PathLike]], WrittenPointer[t.Union[str, os.PathLike]],
                WrittenPointer[str], WrittenPointer[str]]:
            return (
                await sem.ptr(source),
                await sem.ptr(target),
                await sem.ptr(filesystemtype),
                await sem.ptr(data),
            )
        source_ptr, target_ptr, filesystemtype_ptr, data_ptr = await self.ram.perform_batch(op)
        await self.task.mount(source_ptr, target_ptr, filesystemtype_ptr, mountflags, data_ptr)

    async def socket(self, domain: AF, type: SOCK, protocol: int=0) -> FileDescriptor:
        return await self.task.socket(domain, type, protocol)

    async def pipe(self) -> Pipe:
        return await (await self.task.pipe(await self.malloc(Pipe))).read()

    async def socketpair(self, domain: AF, type: SOCK, protocol: int=0) -> Socketpair:
        return await (await self.task.socketpair(domain, type, protocol, await self.malloc(Socketpair))).read()

    async def chroot(self, path: t.Union[str, os.PathLike]) -> None:
        await self.task.chroot(await self.ptr(path))

    def inherit_fd(self, fd: FileDescriptor) -> FileDescriptor:
        return self.task.inherit_fd(fd)

    async def clone(self, flags: CLONE=CLONE.NONE, automatically_write_user_mappings: bool=True) -> ChildThread:
        """Create a new child thread

        manpage: clone(2)
        """
        child_process, task = await clone_child_task(
            self.task, self.ram, self.connection, self.loader, self.monitor,
            flags, lambda sock: Trampoline(self.loader.server_func, [sock, sock]))
        ram = RAM(task,
                  # We don't inherit the transport because it leads to a deadlock:
                  # If when a child task calls transport.read, it performs a syscall in the child task,
                  # then the parent task will need to call waitid to monitor the child task during the syscall,
                  # which will in turn need to also call transport.read.
                  # But the child is already using the transport and holding the lock,
                  # so the parent will block forever on taking the lock,
                  # and child's read syscall will never complete.
                  self.ram.transport,
                  self.ram.allocator.inherit(task),
        )
        if flags & CLONE.NEWPID:
            # if the new process is pid 1, then CLONE_PARENT isn't allowed so we can't use inherit_to_child.
            # if we are a reaper, than we don't want our child CLONE_PARENTing to us, so we can't use inherit_to_child.
            # in both cases we just fall back to making a new ChildProcessMonitor for the child.
            epoller = await Epoller.make_root(ram, task)
            # this signal is already blocked, we inherited the block, um... I guess...
            # TODO handle this more formally
            signal_block = SignalBlock(task, await ram.ptr(Sigset({SIG.CHLD})))
            monitor = await ChildProcessMonitor.make(ram, task, epoller, signal_block=signal_block)
        else:
            epoller = self.epoller.inherit(ram)
            monitor = self.monitor.inherit_to_child(task)
        thread = ChildThread(Thread(
            task, ram,
            self.connection.inherit(task, ram),
            self.loader,
            epoller, monitor,
            self.environ.inherit(task, ram),
            stdin=self.stdin.inherit(task),
            stdout=self.stdout.inherit(task),
            stderr=self.stderr.inherit(task),
        ), child_process)
        if flags & CLONE.NEWUSER and automatically_write_user_mappings:
            # hack, we should really track the [ug]id ahead of this so we don't have to get it
            # we have to get the [ug]id from the parent because it will fail in the child
            uid = await self.task.getuid()
            gid = await self.task.getgid()
            await write_user_mappings(thread, uid, gid)
        return thread

    async def run(self, command: Command, check=True,
                  *, task_status=trio.TASK_STATUS_IGNORED) -> ChildState:
        """Run the passed command to completion and return its end state, throwing if unclean

        If check is False, we won't throw if the end state is unclean.

        """
        thread = await self.clone()
        child = await thread.exec(command)
        task_status.started(child)
        if check:
            return await child.check()
        else:
            return await child.waitpid(W.EXITED)

    async def unshare(self, flags: CLONE) -> None:
        "Call the unshare syscall, appropriately updating values on this class"
        # Note: unsharing NEWPID causes us to not get zombies for our children if init dies. That
        # means we'll get ECHILDs, and various races can happen. It's not possible to robustly
        # unshare NEWPID.
        if flags & CLONE.FILES:
            await self.unshare_files()
            flags ^= CLONE.FILES
        if flags & CLONE.NEWUSER:
            await self.unshare_user()
            flags ^= CLONE.NEWUSER
            if flags & CLONE.FS:
                flags ^= CLONE.FS
        await self.task.unshare(flags)

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
        await self.task.unshare_files()
        if not going_to_exec:
            await do_cloexec_except(self, set([fd.near for fd in self.task.fd_handles]))

    async def unshare_user(self,
                           in_namespace_uid: int=None, in_namespace_gid: int=None) -> None:
        """Unshare the user namespace.

        We automatically set up the user namespace in the unprivileged way using a single user
        mapping line.  You can pass `in_namespace_uid` and `in_namespace_gid` to control what user
        id and group id we'll observe inside the namespace.  If you want further control, call
        task.unshare(CLONE.NEWUSER) directly.

        We also automatically do unshare(CLONE.FS); that's required by CLONE.NEWUSER.

        """
        uid = await self.task.getuid()
        gid = await self.task.getgid()
        await self.task.unshare(CLONE.FS|CLONE.NEWUSER)
        await write_user_mappings(self, uid, gid,
                                  in_namespace_uid=in_namespace_uid, in_namespace_gid=in_namespace_gid)

    async def exit(self, status: int=0) -> None:
        """Exit this thread

        Currently we just forward through to exit the task.

        I feel suspicious that this method will at some point require more heavy lifting with
        namespaces and monitored children, so I'm leaving it on Thread to prepare for that
        eventuality.

        manpage: exit(2)
        """
        await self.task.exit(status)

    def __repr__(self) -> str:
        name = type(self).__name__
        return f'{name}({self.task})'

class ChildThread(Thread):
    "A thread that we know is also a direct child process of another thread"
    def __init__(self, thr: Thread, process: AsyncChildProcess) -> None:
        super()._init_from(thr)
        self.process = process

    async def _execve(self, path: t.Union[str, os.PathLike], argv: t.List[str], envp: t.List[str],
                      command: Command=None,
    ) -> AsyncChildProcess:
        "Call execve, abstracting over memory; self.{exec,execve} are probably preferable"
        async def op(sem: RAM) -> t.Tuple[WrittenPointer[t.Union[str, os.PathLike]],
                                          WrittenPointer[ArgList],
                                          WrittenPointer[ArgList]]:
            argv_ptrs = ArgList([await sem.ptr(arg) for arg in argv])
            envp_ptrs = ArgList([await sem.ptr(arg) for arg in envp])
            return (await sem.ptr(path),
                    await sem.ptr(argv_ptrs),
                    await sem.ptr(envp_ptrs))
        filename, argv_ptr, envp_ptr = await self.ram.perform_batch(op)
        await self.task.execve(filename, argv_ptr, envp_ptr, command=command)
        return self.process

    async def execv(self, path: t.Union[str, os.PathLike],
                    argv: t.Sequence[t.Union[str, os.PathLike]],
                    command: Command=None,
    ) -> AsyncChildProcess:
        """Replace the running executable in this thread with another; see execve.
        """
        async def op(sem: RAM) -> t.Tuple[WrittenPointer[t.Union[str, os.PathLike]], WrittenPointer[ArgList]]:
            argv_ptrs = ArgList([await sem.ptr(arg) for arg in argv])
            return (await sem.ptr(path), await sem.ptr(argv_ptrs))
        filename_ptr, argv_ptr = await self.ram.perform_batch(op)
        envp_ptr = await self.environ.as_arglist(self.ram)
        await self.task.execve(filename_ptr, argv_ptr, envp_ptr, command=command)
        return self.process

    async def execve(self, path: t.Union[str, os.PathLike],
                     argv: t.Sequence[t.Union[str, os.PathLike]],
                     env_updates: t.Mapping[str, t.Union[str, os.PathLike]]={},
                     inherited_signal_blocks: t.List[SignalBlock]=[],
                     command: Command=None,
    ) -> AsyncChildProcess:
        """Replace the running executable in this thread with another.

        self.exec is probably preferable; it takes a nice Command object which
        is easier to work with.

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
        sigmask: t.Set[SIG] = set()
        for block in inherited_signal_blocks:
            sigmask = sigmask.union(block.mask)
        await self.task.sigprocmask((HowSIG.SETMASK, await self.ram.ptr(Sigset(sigmask))))
        if not env_updates:
            # use execv if we aren't updating the env, as an optimization.
            return await self.execv(path, argv, command=command)
        envp: t.Dict[str, str] = {**self.environ.data}
        for key, value in env_updates.items():
            envp[key] = os.fsdecode(value)
        raw_envp: t.List[str] = ['='.join([key, value]) for key, value in envp.items()]
        logger.debug("execveat(%s, %s, %s)", path, argv, env_updates)
        return await self._execve(path, [os.fsdecode(arg) for arg in argv], raw_envp, command=command)

    async def exec(self, command: Command,
                   inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> AsyncChildProcess:
        """Replace the running executable in this thread with what's specified in `command`

        See self.execve's docstring for an explanation of inherited_signal_blocks.

        manpage: execve(2)
        """
        return (await self.execve(command.executable_path, command.arguments, command.env_updates,
                                  inherited_signal_blocks=inherited_signal_blocks, command=command))
