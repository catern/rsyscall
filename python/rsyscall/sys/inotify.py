from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.near.types import WatchDescriptor
from rsyscall.struct import Serializable
import typing as t
from dataclasses import dataclass
import enum

__all__ = [
    "InotifyFlag",
    "IN",
    "InotifyEvent",
    "InotifyEventList",
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

    def to_bytes(self) -> bytes:
        if self.name is not None:
            name = name.encode()
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
