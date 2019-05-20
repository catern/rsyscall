from __future__ import annotations
from rsyscall._raw import lib, ffi # type: ignore
from rsyscall.struct import Struct, Serializable
import enum
import os
import select
import typing as t
from dataclasses import dataclass

class EpollFlag(enum.IntFlag):
    NONE = 0
    CLOEXEC = lib.EPOLL_CLOEXEC

class EPOLL_CTL(enum.IntEnum):
    ADD = lib.EPOLL_CTL_ADD
    MOD = lib.EPOLL_CTL_MOD
    DEL = lib.EPOLL_CTL_DEL

class EPOLL(enum.IntFlag):
    NONE = 0
    IN = select.EPOLLIN
    OUT = select.EPOLLOUT
    RDHUP = select.EPOLLRDHUP # type: ignore
    PRI = select.EPOLLPRI
    ERR = select.EPOLLERR
    HUP = select.EPOLLHUP
    # options
    ET = select.EPOLLET

@dataclass
class EpollEvent(Struct):
    data: int
    events: EPOLL

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct epoll_event const*', (self.events, (self.data,)))))

    T = t.TypeVar('T', bound='EpollEvent')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct epoll_event*', ffi.from_buffer(data))
        return cls(struct.data.u64, EPOLL(struct.events))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct epoll_event')

class EpollEventList(t.List[EpollEvent], Serializable):
    def to_bytes(self) -> bytes:
        ret = b""
        for ent in self:
            ret += ent.to_bytes()
        return ret

    T = t.TypeVar('T', bound='EpollEventList')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        entries = []
        while len(data) > 0:
            ent = EpollEvent.from_bytes(data)
            entries.append(ent)
            data = data[EpollEvent.sizeof():]
        return cls(entries)


#### Tests ####
from unittest import TestCase
class TestEpoll(TestCase):
    def test_epoll_event_list(self) -> None:
        initial = EpollEventList([EpollEvent(42, EPOLL.IN|EPOLL.PRI)])
        output = EpollEventList.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
