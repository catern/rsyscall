from rsyscall._raw import lib # type: ignore
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

#### Classes ####
import rsyscall.far
from rsyscall.handle.pointer import WrittenPointer
from rsyscall.unistd import Arg

class MountTask(rsyscall.far.Task):
    async def mount(self,
                    source: WrittenPointer[Arg], target: WrittenPointer[Arg],
                    filesystemtype: WrittenPointer[Arg], mountflags: MS,
                    data: WrittenPointer[Arg]) -> None:
        with source.borrow(self):
            with target.borrow(self):
                with filesystemtype.borrow(self):
                    with data.borrow(self):
                        return (await _mount(
                            self.sysif,
                            source.near, target.near, filesystemtype.near,
                            mountflags, data.near))

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _mount(sysif: SyscallInterface, source: near.Address, target: near.Address,
                 filesystemtype: near.Address, mountflags: MS,
                 data: near.Address) -> None:
    await sysif.syscall(SYS.mount, source, target, filesystemtype, mountflags, data)
