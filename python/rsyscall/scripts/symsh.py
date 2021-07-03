"A program developed for SIGBOVIK2020; see research/sigbovik2020 for more information."
from __future__ import annotations
import shlex

from rsyscall.sched import CLONE
from rsyscall.fcntl import O
from rsyscall.unistd import SEEK
from rsyscall.path import Path
from rsyscall.stdlib import mkdtemp
from rsyscall.sys.mount import MS, UMOUNT
from rsyscall.sys.stat import Stat
from rsyscall.near.sysif import SyscallError

from rsyscall.linux.fuse import (
    FuseOut,
    FuseInitOp, FuseLookupOp, FuseOpenOp, FuseOpendirOp, FuseReadOp, FuseGetattrOp, FuseReaddirplusOp, FuseFlushOp, FuseReleaseOp, FuseReleasedirOp, FuseReadlinkOp, FuseGetxattrOp,
    FuseInList, FuseInitIn, FuseInitOut, FuseAttr, FuseEntryOut, FuseOpenOut, FOPEN,
    FuseAttrOut,
    FuseDirentplus, FuseDirent,
    FUSE_INIT,
    FUSE_MIN_READ_BUFFER,
)
from rsyscall.linux.dirent import DirentList, DT
from rsyscall.time import Timespec
from rsyscall.sys.stat import TypeMode, S_IF, Mode
from rsyscall import Command, WrittenPointer, FileDescriptor, Thread
from rsyscall.memory.ram import RAM
from rsyscall.unistd import AT, ArgList
from rsyscall.tasks.stub import StubServer
import errno
import os
import trio
import typing as t
import logging

logger = logging.getLogger(__name__)

from dataclasses import dataclass
@dataclass
class CommandData:
    args: t.List[str]
    stdin: Stat
    stdout: Stat
    stderr: Stat

def reconstruct(commands: t.List[CommandData]) -> str:
    script = ""
    for i in range(len(commands)):
        if i == 0:
            # there's no guarantee that they'll exec in order, lol, but this makes for simpler code
            script += " ".join(commands[0].args)
            stdin = commands[0].stdin
        else:
            prev = commands[i-1]
            cur = commands[i]
            if prev.stdout.ino == cur.stdin.ino and cur.stdin.ino != stdin.ino:
                # it also doubles as a pretty printer
                script += " | "
            else:
                script += "\n"
            script += " ".join(commands[i].args)
    script += "\n"
    return script

import argparse

class FuseFS:
    @classmethod
    async def mount(cls, thread: Thread, path: Path) -> FuseFS:
        self = cls()
        await self._mount(thread, path)
        return self

    async def _mount(self, thread: Thread, path: Path) -> None:
        # TODO does a pid namespace kill a thread in D-wait?
        # TODO we could make a better API here with the new mount API
        self.path = path
        # /dev/fuse doesn't seem to behave nicely when used with EPOLLET, so we'll just do blocking
        # IO on it in a dedicated thread - we need the dedicated thread anyway (see comment below
        # about private fd table) so it's not extra overhead.
        devfuse = await thread.task.open(await thread.ptr(Path("/dev/fuse")), O.RDWR)
        self.uid = await thread.task.getuid()
        self.gid = await thread.task.getgid()
        self.parent_thread = thread
        await thread.mount("ignored", self.path, "fuse", MS.NONE,
                           f"fd={int(devfuse)},rootmode=40777,user_id={self.uid},group_id={self.gid}")
        # We'll keep devfuse open *only* in the dedicated server thread's private fd table, so that
        # other threads accessing the filesystem don't deadlock when we abort the FUSE server loop -
        # instead their syscalls will be aborted with ENOTCONN.
        self.thr = await thread.clone()
        self.devfuse = self.thr.task.inherit_fd(devfuse)
        await devfuse.close()
        # Respond to FUSE init message to sanity-check things are set up right.
        self.buf = await self.thr.malloc(FuseInList, FUSE_MIN_READ_BUFFER)
        [init] = await self.read()
        if not isinstance(init, FuseInitOp):
            raise Exception("oops, got non-init as first message", init)
        flags = init.msg.flags & ~(FUSE_INIT.EXPORT_SUPPORT)
        # /dev/fuse doesn't ever do partial writes, nice.
        await self.write(init.respond(FuseInitOut(
            major=init.msg.major, minor=init.msg.minor, max_readahead=init.msg.max_readahead,
            flags=flags,
            max_background=16, congestion_threshold=16, max_write=128, time_gran=128)))
        # Note that deadlocks are still possible, if the root thread makes blocking calls into the
        # filesystem. As usual, we should avoid doing work on the root thread, and instead do it in
        # children.

    async def read(self) -> FuseInList:
        # /dev/fuse only returns complete packets, so we don't need to rebuffer, wonderful.
        read, unused = await self.devfuse.read(self.buf)
        msgs = await read.read()
        logger.debug("read in FUSE messages: %s", msgs)
        self.buf = read + unused
        return msgs

    async def write(self, out: FuseOut) -> None:
        logger.debug("writing out FUSE response: %s", out)
        ptr = await self.thr.ptr(out)
        written, unwritten = await self.devfuse.write(ptr)
        if unwritten.size() != 0:
            raise Exception("/dev/fuse is not supposed to ever do partial writes, but I got one somehow on", ptr)

    async def __aenter__(self) -> FuseFS:
        return self

    async def cleanup(self) -> None:
        # umount to kill the fuse loop; it's a bit lazy to save the parent thread to do this, but we
        # can't do it in self.thr because that thread spends all its time blocked in read.
        await self.parent_thread.task.umount(await self.parent_thread.ptr(self.path))
        # and exit the thread - but it might already be dead, so we might fail to exit it, just ignore that.
        try:
            await self.thr.exit(0)
        except SyscallError:
            pass

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.cleanup()

    def __init__(self) -> None:
        pass

async def symsh_main(thread: Thread, command: Command) -> None:
    async with (await mkdtemp(thread)) as tmpdir:
        thr = await thread.clone(flags=CLONE.NEWUSER|CLONE.NEWNS)
        path = tmpdir/"path"
        await thr.mkdir(path)
        async with trio.open_nursery() as nursery:
            stub_server = await StubServer.make(thr, tmpdir, "stub")
            stub_path = tmpdir/"stub"
            commands: t.List[CommandData] = []
            @nursery.start_soon
            async def exec_server() -> None:
                """Accepts connections from the stub executables

                We just check the command and stat stdin/stdout/stderr, then exit the stub.

                """
                while True:
                    args, thread = await stub_server.accept()
                    buf = await thread.malloc(Stat)
                    async def stat(fd: FileDescriptor) -> Stat:
                        nonlocal buf
                        buf = await fd.fstat(buf)
                        return await buf.read()
                    name, *rest = args
                    commands.append(CommandData(
                        args=[Path(name).name, *rest],
                        stdin=await stat(thread.stdin),
                        stdout=await stat(thread.stdout),
                        stderr=await stat(thread.stderr),
                    ))
                    await thread.exit(0)
            async with (await FuseFS.mount(thr, path)) as fuse:
                @nursery.start_soon
                async def open() -> None:
                    "Every filename in this filesystem is a symlink to stub_path"
                    while True:
                        try:
                            [op] = await fuse.read()
                        except OSError as e:
                            # sure wish Python had a builtin ENODEV exception, that would come in handy
                            if e.errno == errno.ENODEV:
                                # the filesystem has been unmounted, just return cleanly
                                return
                            else:
                                raise
                        sym_ino = 2
                        fh = 42
                        if isinstance(op, FuseGetattrOp):
                            await fuse.write(op.respond(FuseAttrOut(
                                attr_valid=Timespec(10000, 0),
                                attr=FuseAttr(
                                    ino=1, size=0, blocks=1,
                                    atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                                    mode=TypeMode(S_IF.DIR, Mode(0o777)), nlink=1,
                                    uid=fuse.uid, gid=fuse.gid, rdev=0, blksize=4096
                                ))))
                        elif isinstance(op, FuseLookupOp):
                            await fuse.write(op.respond(FuseEntryOut(
                                nodeid=sym_ino, generation=1,
                                entry_valid=Timespec(10000, 0), attr_valid=Timespec(10000, 0),
                                # the size needs to be consistent with the data we'll actually send back on read
                                # the kernel, I guess, handles delivering an eof
                                attr=FuseAttr(
                                    ino=999, size=16, blocks=1,
                                    atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                                    mode=TypeMode(S_IF.LNK, Mode(0o777)), nlink=1,
                                    uid=fuse.uid, gid=fuse.gid, rdev=0, blksize=4096
                                ))))
                        elif isinstance(op, FuseOpenOp):
                            await fuse.write(op.respond(FuseOpenOut(fh=fh, open_flags=FOPEN.NONE)))
                        elif isinstance(op, FuseGetxattrOp):
                            await fuse.write(op.error(-errno.ENODATA))
                        elif isinstance(op, FuseReadOp):
                            await fuse.write(op.respond(bytes(16)))
                        elif isinstance(op, FuseReleaseOp):
                            await fuse.write(op.respond())
                        elif isinstance(op, FuseReadlinkOp):
                            await fuse.write(op.respond(stub_path))
                        else:
                            print("unhandled op", op)
                            raise Exception("unhandled op", op)
                # now we simply run the command with PATH set to only our FUSE path, and boom
                await thr.run(command.env(PATH=path))
                print("==================== reconstructed script ====================")
                print(reconstruct(commands), end='')
            nursery.cancel_scope.cancel()

async def amain(argv: t.List[str]) -> None:
    # hmm I should write a more TFS/direct style argument parser for python
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='subcommand', required=True)
    
    example_parser = subparsers.add_parser('example', help='Example')
    exec_parser = subparsers.add_parser('exec', help="Exec the provided executable, no arguments allowed")
    exec_parser.add_argument(dest='executable')
    
    args = parser.parse_args(argv[1:])
    from rsyscall import local_thread
    if args.subcommand == 'example':
        script = """ls; which ls
stat /
foo|bar
"""
        print("======================= running script =======================")
        print(script, end='')
        await symsh_main(local_thread, local_thread.environ.sh.args("-c", script))
    elif args.subcommand == 'exec':
        await symsh_main(local_thread, Command(Path(args.executable), [args.executable], {}))

def main():
    import sys
    trio.run(amain, sys.argv)

if __name__ == "__main__":
    main()
