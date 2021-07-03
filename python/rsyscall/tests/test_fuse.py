from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
import shlex

from rsyscall.sched import CLONE
from rsyscall.fcntl import O
from rsyscall.unistd import SEEK
from rsyscall.stdlib import mkdtemp
from rsyscall.sys.mount import MS
from rsyscall.sys.stat import Stat

from rsyscall.linux.fuse import (
    FuseInitOp, FuseLookupOp, FuseOpenOp, FuseOpendirOp, FuseReadOp, FuseGetattrOp, FuseReaddirplusOp, FuseFlushOp, FuseReleaseOp, FuseReleasedirOp, FuseReadlinkOp, FuseGetxattrOp,
    FuseIn, FuseInList, FuseInitIn, FuseInitOut, FuseAttr, FuseEntryOut, FuseOpenOut, FOPEN,
    FuseAttrOut,
    FuseDirentplus, FuseDirent,
    FUSE_INIT,
)
from rsyscall.linux.dirent import DirentList, DT
from rsyscall.time import Timespec
from rsyscall.sys.stat import TypeMode, S_IF, Mode
from rsyscall import Command, WrittenPointer, FileDescriptor
from rsyscall.memory.ram import RAM
from rsyscall.unistd import AT, ArgList
from rsyscall.tasks.stub import StubServer
from rsyscall.scripts.symsh import FuseFS
import errno
import os
import trio
import typing as t
from dataclasses import dataclass
import unittest

class TestFUSE(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmpdir = await mkdtemp(local_thread)
        self.thr = await local_thread.clone(CLONE.NEWUSER|CLONE.NEWNS)
        self.child = await self.thr.clone()
        self.path = self.tmpdir/"path"
        await self.thr.mkdir(self.path)
        self.fuse = await FuseFS.mount(self.thr, self.path)

    async def asyncTearDown(self) -> None:
        await self.fuse.thr.process.kill()
        await self.fuse.cleanup()
        await self.tmpdir.cleanup()

    T_fusein = t.TypeVar('T_fusein', bound=FuseIn)
    async def assertRead(self, cls: t.Type[T_fusein]) -> T_fusein:
        [op] = await self.fuse.read()
        if not isinstance(op, cls):
            raise Exception("expected", cls, "got", op)
        return op

    async def test_basic(self) -> None:
        data_read_from_fuse = b"this is some data read from fuse"
        @self.nursery.start_soon
        async def open() -> None:
            foo = await self.child.task.open(await self.child.ptr(self.path/"foo"), O.RDONLY)
            data, _ = await foo.read(await self.child.malloc(bytes, 4096))
            self.assertEqual(data_read_from_fuse, await data.read())
            data, _ = await foo.read(await self.child.malloc(bytes, 4096))
            self.assertEqual(data.size(), 0)
            await foo.close()

            root = await self.child.task.open(await self.child.ptr(self.path), O.RDONLY)
            valid, rest = await root.getdents(await self.child.ram.malloc(DirentList, 4096))
            await root.close()
        root_getattr = await self.assertRead(FuseGetattrOp)
        if root_getattr.hdr.nodeid != 1:
            raise Exception("expected to get getattr for root node 1,  not", root_getattr.hdr.nodeid)
        await self.fuse.write(root_getattr.respond(FuseAttrOut(
            attr_valid=Timespec(10000, 0),
            attr=FuseAttr(
                ino=1, size=0, blocks=1,
                atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                mode=TypeMode(S_IF.DIR, Mode(0o777)), nlink=1,
                uid=self.fuse.uid, gid=self.fuse.gid, rdev=0, blksize=4096
            ))))
        await self.fuse.write((await self.assertRead(FuseLookupOp)).respond(FuseEntryOut(
            nodeid=2, generation=1,
            entry_valid=Timespec(10000, 0), attr_valid=Timespec(10000, 0),
            # the size needs to be consistent with the data we'll actually send back on read
            # the kernel, I guess, handles delivering an eof
            attr=FuseAttr(
                ino=999, size=len(data_read_from_fuse), blocks=1,
                atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                mode=TypeMode(S_IF.REG, Mode(0o777)), nlink=1, uid=self.fuse.uid, gid=self.fuse.gid, rdev=0, blksize=4096
            ))))
        fh = 42
        await self.fuse.write((await self.assertRead(FuseOpenOp)).respond(FuseOpenOut(fh=fh, open_flags=FOPEN.NONE)))
        await self.fuse.write((await self.assertRead(FuseReadOp)).respond(data_read_from_fuse))
        # close file
        await self.fuse.write((await self.assertRead(FuseFlushOp)).respond())
        await self.fuse.write((await self.assertRead(FuseReleaseOp)).respond())
        # open root and getdents
        root_fh = 137
        await self.fuse.write((await self.assertRead(FuseOpendirOp)).respond(FuseOpenOut(fh=root_fh, open_flags=FOPEN.NONE)))
        foobar_ino = 432
        await self.fuse.write((await self.assertRead(FuseReaddirplusOp)).respond([
            FuseDirentplus(
                FuseEntryOut(
                    nodeid=foobar_ino, generation=1,
                    entry_valid=Timespec(10000, 0), attr_valid=Timespec(10000, 0),
                    # the size needs to be consistent with the data we'll actually send back on read
                    # the kernel, I guess, handles delivering an eof
                    attr=FuseAttr(
                        ino=foobar_ino, size=len(data_read_from_fuse), blocks=1,
                        atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                        mode=TypeMode(S_IF.REG, Mode(0o777)), nlink=1, uid=self.fuse.uid, gid=self.fuse.gid, rdev=0, blksize=4096
                    )),
                FuseDirent(
                    ino=foobar_ino,
                    off=1,
                    type=DT.REG,
                    name="foobar",
                ),
            ),
        ]))
        # close file
        await self.fuse.write((await self.assertRead(FuseReleasedirOp)).respond())

    async def test_symlink(self) -> None:
        @self.nursery.start_soon
        async def open() -> None:
            async with (await self.child.task.open(await self.thr.ptr(self.path/"foo"), O.RDONLY)) as foo:
                data, _ = await foo.read(await self.thr.malloc(bytes, 4096))
        await self.fuse.write((await self.assertRead(FuseGetattrOp)).respond(FuseAttrOut(
            attr_valid=Timespec(10000, 0),
            attr=FuseAttr(
                ino=1, size=0, blocks=1,
                atime=Timespec(0, 0), mtime=Timespec(0, 0), ctime=Timespec(0, 0),
                mode=TypeMode(S_IF.DIR, Mode(0o777)), nlink=1,
                uid=self.fuse.uid, gid=self.fuse.gid, rdev=0, blksize=4096
            ))))
        await self.fuse.write((await self.assertRead(FuseLookupOp)).respond(FuseEntryOut(
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
        await self.fuse.write((await self.assertRead(FuseReadlinkOp)).respond("/bin/sh"))
