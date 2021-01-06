"`#include <sys/inotify.h>`"
from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.limits import NAME_MAX
from rsyscall.near.types import WatchDescriptor
from rsyscall.struct import Serializable
import typing as t
from dataclasses import dataclass
import enum
import os

__all__ = [
    "InotifyFlag",
    "IN",
    "InotifyEvent",
    "InotifyEventList",
    "InotifyFileDescriptor",
]

class InotifyFlag(enum.IntFlag):
    NONE = 0
    CLOEXEC = lib.IN_CLOEXEC
    NONBLOCK = lib.IN_NONBLOCK

class IN(enum.IntFlag):
    # possible events, specified in inotify_add_watch and returned in struct inotify_event
    ACCESS = lib.IN_ACCESS
    ATTRIB = lib.IN_ATTRIB
    CLOSE_WRITE = lib.IN_CLOSE_WRITE
    CLOSE_NOWRITE = lib.IN_CLOSE_NOWRITE
    CREATE = lib.IN_CREATE
    DELETE = lib.IN_DELETE
    DELETE_SELF = lib.IN_DELETE_SELF
    MODIFY = lib.IN_MODIFY
    MOVE_SELF = lib.IN_MOVE_SELF
    MOVED_FROM = lib.IN_MOVED_FROM
    MOVED_TO = lib.IN_MOVED_TO
    OPEN = lib.IN_OPEN
    # additional options to inotify_add_watch
    DONT_FOLLOW = lib.IN_DONT_FOLLOW
    EXCL_UNLINK = lib.IN_EXCL_UNLINK
    MASK_ADD = lib.IN_MASK_ADD
    ONESHOT = lib.IN_ONESHOT
    ONLYDIR = lib.IN_ONLYDIR
    # additional bits returned in struct inotify_event 
    IGNORED = lib.IN_IGNORED
    ISDIR = lib.IN_ISDIR
    Q_OVERFLOW = lib.IN_Q_OVERFLOW
    UNMOUNT = lib.IN_UNMOUNT

@dataclass
class InotifyEvent:
    wd: WatchDescriptor
    mask: IN
    cookie: int
    name: t.Optional[str]
    MINIMUM_SIZE_TO_READ_ONE_EVENT = ffi.sizeof('struct inotify_event') + NAME_MAX + 1

    def to_bytes(self) -> bytes:
        if self.name is not None:
            name = self.name.encode()
            name_len = len(name)
        else:
            name = b""
            name_len = 0
        return bytes(ffi.buffer(ffi.new('struct inotify_event*', {
            "wd": self.wd,
            "mask": self.mask,
            "cookie": self.cookie,
            "len": name_len,
            "name": name,
        })))

    T = t.TypeVar('T', bound='InotifyEvent')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> t.Tuple[T, int]:
        struct = ffi.cast('struct inotify_event*', ffi.from_buffer(data))
        value = cls(
            wd=WatchDescriptor(struct.wd),
            mask=IN(struct.mask),
            cookie=struct.cookie,
            name=ffi.string(struct.name, struct.len).decode() if struct.len else None,
        )
        size = ffi.sizeof("struct inotify_event") + struct.len
        return value, size

class InotifyEventList(t.List[InotifyEvent], Serializable):
    def to_bytes(self) -> bytes:
        ret = b""
        for ent in self:
            ret += ent.to_bytes()
        return ret

    T = t.TypeVar('T', bound='InotifyEventList')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        entries = []
        while len(data) > 0:
            ent, size = InotifyEvent.from_bytes(data)
            entries.append(ent)
            data = data[size:]
        return cls(entries)

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask
from rsyscall.handle.pointer import Pointer, WrittenPointer

T_fd = t.TypeVar('T_fd', bound='InotifyFileDescriptor')
class InotifyFileDescriptor(BaseFileDescriptor):
    async def inotify_add_watch(self,
                                pathname: WrittenPointer[t.Union[str, os.PathLike]], mask: IN) -> WatchDescriptor:
        self._validate()
        with pathname.borrow(self.task):
            return (await _inotify_add_watch(self.task.sysif, self.near, pathname.near, mask))

    async def inotify_rm_watch(self, wd: WatchDescriptor) -> None:
        self._validate()
        await _inotify_rm_watch(self.task.sysif, self.near, wd)

class InotifyTask(FileDescriptorTask[T_fd]):
    async def inotify_init(self, flags: InotifyFlag=InotifyFlag.NONE) -> T_fd:
        return self.make_fd_handle(await _inotify_init(self.sysif, flags|InotifyFlag.CLOEXEC))

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _inotify_init(sysif: SyscallInterface, flags: InotifyFlag) -> near.FileDescriptor:
    return near.FileDescriptor(await sysif.syscall(SYS.inotify_init1, flags))

async def _inotify_add_watch(sysif: SyscallInterface, fd: near.FileDescriptor,
                             pathname: near.Address, mask: IN) -> WatchDescriptor:
    return WatchDescriptor(await sysif.syscall(SYS.inotify_add_watch, fd, pathname, mask))

async def _inotify_rm_watch(sysif: SyscallInterface, fd: near.FileDescriptor,
                            wd: WatchDescriptor) -> None:
    await sysif.syscall(SYS.inotify_rm_watch, fd, wd)
