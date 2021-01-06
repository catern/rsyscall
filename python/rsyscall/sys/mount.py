"`#include <sys/mount.h>`"
from rsyscall._raw import lib # type: ignore
import os
import typing as t
import enum

class MS(enum.IntFlag):
    NONE = 0
    BIND = lib.MS_BIND
    DIRSYNC = lib.MS_DIRSYNC
    LAZYTIME = lib.MS_LAZYTIME
    MANDLOCK = lib.MS_MANDLOCK
    MOVE = lib.MS_MOVE
    NODEV = lib.MS_NODEV
    NOEXEC = lib.MS_NOEXEC
    NOSUID = lib.MS_NOSUID
    RDONLY = lib.MS_RDONLY
    REC = lib.MS_REC
    RELATIME = lib.MS_RELATIME
    REMOUNT = lib.MS_REMOUNT
    SILENT = lib.MS_SILENT
    SLAVE = lib.MS_SLAVE
    STRICTATIME = lib.MS_STRICTATIME
    SYNCHRONOUS = lib.MS_SYNCHRONOUS
    UNBINDABLE = lib.MS_UNBINDABLE

class UMOUNT(enum.IntFlag):
    NONE = 0
    FORCE = lib.MNT_FORCE
    DETACH = lib.MNT_DETACH
    EXPIRE = lib.MNT_EXPIRE
    NOFOLLOW = lib.UMOUNT_NOFOLLOW

#### Classes ####
import rsyscall.far
from rsyscall.handle.pointer import WrittenPointer

class MountTask(rsyscall.far.Task):
    async def mount(self,
                    source: WrittenPointer[t.Union[str, os.PathLike]],
                    target: WrittenPointer[t.Union[str, os.PathLike]],
                    filesystemtype: WrittenPointer[t.Union[str, os.PathLike]],
                    mountflags: MS,
                    data: WrittenPointer[t.Union[str, os.PathLike]]) -> None:
        with source.borrow(self):
            with target.borrow(self):
                with filesystemtype.borrow(self):
                    with data.borrow(self):
                        try:
                            return (await _mount(
                                self.sysif,
                                source.near, target.near, filesystemtype.near,
                                mountflags, data.near))
                        except OSError as exn:
                            exn.filename = source.value
                            exn.filename2 = (target.value, filesystemtype.value, data.value)
                            raise

    async def umount(self, target: WrittenPointer[t.Union[str, os.PathLike]], flags: UMOUNT=UMOUNT.NONE) -> None:
        with target.borrow(self):
            await _umount2(self.sysif, target.near, flags)

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _mount(sysif: SyscallInterface, source: near.Address, target: near.Address,
                 filesystemtype: near.Address, mountflags: MS,
                 data: near.Address) -> None:
    await sysif.syscall(SYS.mount, source, target, filesystemtype, mountflags, data)

async def _umount2(sysif: SyscallInterface, target: near.Address, flags: UMOUNT) -> None:
    await sysif.syscall(SYS.umount2, target, flags)
