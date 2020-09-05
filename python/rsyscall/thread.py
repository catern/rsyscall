"Central thread class, with helper methods to ease a number of common tasks"
from __future__ import annotations
from dataclasses import dataclass
from rsyscall.command import Command
from rsyscall.handle import FileDescriptor, Path, WrittenPointer, Pointer, Task
from rsyscall.memory.ram import RAM, RAMThread
from rsyscall.mktemp import mkdtemp, TemporaryDirectory
from rsyscall.unix_thread import UnixThread, ChildUnixThread
import os
import rsyscall.near.types as near
import rsyscall.near
import trio
import typing as t

from rsyscall.fcntl import O, F, FD_CLOEXEC, _fcntl
from rsyscall.linux.dirent import DirentList
from rsyscall.sched import CLONE
from rsyscall.sys.mount import MS
from rsyscall.sys.wait import ChildState, W
from rsyscall.sys.socket import Socketpair, AF, SOCK
from rsyscall.unistd import Arg, Pipe

async def write_user_mappings(thr: RAMThread, uid: int, gid: int,
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

async def do_cloexec_except(thr: RAMThread, excluded_fds: t.Set[near.FileDescriptor]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    # it's important to do this so we can't try to inherit the fds that we close here
    thr.task.fd_table.remove_inherited()
    buf = await thr.ram.malloc(DirentList, 4096)
    dirfd = await thr.task.open(await thr.ram.ptr(Path("/proc/self/fd")), O.DIRECTORY)
    async def maybe_close(fd: near.FileDescriptor) -> None:
        flags = await _fcntl(thr.task.sysif, fd, F.GETFD)
        if (flags & FD_CLOEXEC) and (fd not in excluded_fds):
            await rsyscall.near.close(thr.task.sysif, fd)
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

class Thread(UnixThread):
    "A central class holding everything necessary to work with some thread, along with various helpers"
    async def mkdtemp(self, prefix: str="mkdtemp") -> TemporaryDirectory:
        "Make a temporary directory by calling rsyscall.mktemp.mkdtemp"
        return await mkdtemp(self, prefix)

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

    async def mount(self, source: t.Union[Path, str], target: t.Union[Path, str],
                    filesystemtype: str, mountflags: MS,
                    data: str) -> None:
        "Call mount with these args"
        async def op(sem: RAM) -> t.Tuple[
                WrittenPointer[Arg], WrittenPointer[Arg], WrittenPointer[Arg], WrittenPointer[Arg]]:
            return (
                await sem.ptr(Arg(source)),
                await sem.ptr(Arg(target)),
                await sem.ptr(Arg(filesystemtype)),
                await sem.ptr(Arg(data)),
            )
        source_ptr, target_ptr, filesystemtype_ptr, data_ptr = await self.ram.perform_batch(op)
        await self.task.mount(source_ptr, target_ptr, filesystemtype_ptr, mountflags, data_ptr)

    async def socket(self, domain: AF, type: SOCK, protocol: int=0) -> FileDescriptor:
        return await self.task.socket(domain, type, protocol)

    async def pipe(self) -> Pipe:
        return await (await self.task.pipe(await self.malloc(Pipe))).read()

    async def socketpair(self, domain: AF, type: SOCK, protocol: int=0) -> Socketpair:
        return await (await self.task.socketpair(domain, type, protocol, await self.malloc(Socketpair))).read()

    async def chroot(self, path: Path) -> None:
        await self.task.chroot(await self.ptr(path))

    def inherit_fd(self, fd: FileDescriptor) -> FileDescriptor:
        return self.task.inherit_fd(fd)

    async def clone(self, flags: CLONE=CLONE.NONE) -> ChildThread:
        """Create a new child thread

        manpage: clone(2)
        """
        thread = await super().clone(flags=flags)
        if flags & CLONE.NEWUSER:
            # hack, we should really track the [ug]id ahead of this so we don't have to get it
            # we have to get the [ug]id from the parent because it will fail in the child
            uid = await self.task.getuid()
            gid = await self.task.getgid()
            await write_user_mappings(thread, uid, gid)
        return ChildThread(thread, thread.process)

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

    async def exit(self, status: int) -> None:
        """Exit this thread

        Currently we just forward through to exit the task.

        I feel suspicious that this method will at some point require more heavy lifting with
        namespaces and monitored children, so I'm leaving it on Thread to prepare for that
        eventuality.

        manpage: exit(2)
        """
        await self.task.exit(status)

    async def close(self) -> None:
        """Close this thread

        Currently we just forward through to close the task.

        """
        await self.task.close_task()

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs):
        await self.close()

    def __repr__(self) -> str:
        name = type(self).__name__
        return f'{name}({self.task})'

class ChildThread(Thread, ChildUnixThread):
    "A thread that we know is also a direct child process of another thread"
    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()
