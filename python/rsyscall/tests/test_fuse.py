from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.nix import local_store
import shlex

from rsyscall.sched import CLONE
from rsyscall.fcntl import O
from rsyscall.unistd import SEEK
from rsyscall.path import EmptyPath, Path
from rsyscall.sys.mount import MS
from rsyscall.sys.stat import Stat

from rsyscall.linux.fuse import (
    FuseInitOp, FuseLookupOp, FuseOpenOp, FuseOpendirOp, FuseReadOp, FuseGetattrOp, FuseReaddirplusOp, FuseFlushOp, FuseReleaseOp, FuseReleasedirOp, FuseReadlinkOp, FuseGetxattrOp,
    FuseInList, FuseInitIn, FuseInitOut, FuseAttr, FuseEntryOut, FuseOpenOut, FOPEN,
    FuseAttrOut,
    FuseDirentplus, FuseDirent,
    FUSE_INIT,
)
from rsyscall.linux.dirent import DirentList, DT
from rsyscall.time import Timespec
from rsyscall.sys.stat import TypeMode, S_IF, Mode
from rsyscall import Command, WrittenPointer, FileDescriptor
from rsyscall.memory.ram import RAM
from rsyscall.unistd import AT, Path, ArgList, Arg
from rsyscall.tasks.stub import StubServer
from rsyscall.scripts.symsh import FuseFS
import errno
import os
import trio
import typing as t
from dataclasses import dataclass

class TestFUSE(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await local.thread.mkdtemp()
        self.thr = await local.thread.clone(flags=CLONE.NEWUSER|CLONE.NEWNS)
        self.child = await self.thr.clone()
        self.path = self.tmpdir.path/"path"
        await self.thr.mkdir(self.path)
        self.fuse = await FuseFS.mount(self.thr, self.path)

    async def asyncTearDown(self) -> None:
        await self.fuse.thr.process.kill()
        await self.fuse.cleanup()
        await self.tmpdir.cleanup()

    async def test_symlink(self) -> None:
        @self.nursery.start_soon
        async def open() -> None:
            async with (await self.child.task.open(await self.thr.ptr(self.path/"foo"), O.RDONLY)) as foo:
                data, _ = await foo.read(await self.thr.malloc(bytes, 4096))
        [root_getattr] = await self.fuse.read()
        if not isinstance(root_getattr, FuseGetattrOp):
            raise Exception("expected FuseGetattrOp, got", root_getattr)
        await self.fuse.write(root_getattr.respond(FuseAttrOut(
            attr_valid=Timespec(10000, 0),
            attr=FuseAttr(
                ino=1, size=0, blocks=1,
                atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                mode=TypeMode(S_IF.DIR, Mode(0o777)), nlink=1,
                uid=self.fuse.uid, gid=self.fuse.gid, rdev=0, blksize=4096
            ))))
        [lookup] = await self.fuse.read()
        if not isinstance(lookup, FuseLookupOp):
            raise Exception("expected FuseLookupOp, got", lookup)
        await self.fuse.write(lookup.respond(FuseEntryOut(
            nodeid=2, generation=1,
            entry_valid=Timespec(10000, 0), attr_valid=Timespec(10000, 0),
            # the size needs to be consistent with the data we'll actually send back on read
            # the kernel, I guess, handles delivering an eof;
            # we can just claim a larger size then send back less data
            attr=FuseAttr(
                ino=999, size=4096, blocks=1,
                atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                mode=TypeMode(S_IF.LNK, Mode(0o777)), nlink=1,
                uid=self.fuse.uid, gid=self.fuse.gid, rdev=0, blksize=4096
            ))))
        [readlink] = await self.fuse.read()
        if not isinstance(readlink, FuseReadlinkOp):
            raise Exception("expected FuseReadlinkOp, got", readlink)
        await self.fuse.write(readlink.respond(Path("/bin/sh")))
