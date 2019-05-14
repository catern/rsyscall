from __future__ import annotations
from dataclasses import dataclass
from rsyscall.batch import BatchSemantics
from rsyscall.command import Command
from rsyscall.handle import FileDescriptor, Path, WrittenPointer, Pointer, Task
from rsyscall.memory.ram import RAM, RAMThread
from rsyscall.mktemp import mkdtemp, TemporaryDirectory
from rsyscall.struct import Bytes
from rsyscall.unix_thread import UnixThread, ChildUnixThread
import os
import rsyscall.near as near
import trio
import typing as t

from rsyscall.fcntl import O, F, FD_CLOEXEC
from rsyscall.linux.dirent import DirentList
from rsyscall.sched import UnshareFlag
from rsyscall.sys.mount import MS
from rsyscall.sys.wait import ChildEvent
from rsyscall.unistd import Arg

async def write_user_mappings(thr: RAMThread, uid: int, gid: int,
                              in_namespace_uid: int=None, in_namespace_gid: int=None) -> None:
    if in_namespace_uid is None:
        in_namespace_uid = uid
    if in_namespace_gid is None:
        in_namespace_gid = gid
    procself = Path("/proc/self")

    uid_map = await thr.task.open(await thr.ram.to_pointer(procself/"uid_map"), O.WRONLY)
    await uid_map.write(await thr.ram.to_pointer(Bytes(f"{in_namespace_uid} {uid} 1\n".encode())))
    await uid_map.close()

    setgroups = await thr.task.open(await thr.ram.to_pointer(procself/"setgroups"), O.WRONLY)
    await setgroups.write(await thr.ram.to_pointer(Bytes(b"deny")))
    await setgroups.close()

    gid_map = await thr.task.open(await thr.ram.to_pointer(procself/"gid_map"), O.WRONLY)
    await gid_map.write(await thr.ram.to_pointer(Bytes(f"{in_namespace_gid} {gid} 1\n".encode())))
    await gid_map.close()

async def do_cloexec_except(thr: RAMThread, excluded_fds: t.Set[near.FileDescriptor]) -> None:
    "Close all CLOEXEC file descriptors, except for those in a whitelist. Would be nice to have a syscall for this."
    buf = await thr.ram.malloc_type(DirentList, 4096)
    dirfd = await thr.task.open(await thr.ram.to_pointer(Path("/proc/self/fd")), O.DIRECTORY|O.CLOEXEC)
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

class Thread(UnixThread):
    @property
    def ramthr(self) -> RAMThread:
        return self

    async def mkdtemp(self, prefix: str="mkdtemp") -> TemporaryDirectory:
        return await mkdtemp(self, prefix)

    async def spit(self, path: Path, text: t.Union[str, bytes], mode=0o644) -> Path:
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
        def op(sem: BatchSemantics) -> t.Tuple[
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

    async def unshare_files_and_replace(self, mapping: t.Dict[FileDescriptor, FileDescriptor],
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

    async def setns_user(self, fd: FileDescriptor) -> None:
        await self.task.base.setns_user(fd)

    async def unshare_mount(self) -> None:
        await self.task.unshare_mount()

    async def setns_mount(self, fd: FileDescriptor) -> None:
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
