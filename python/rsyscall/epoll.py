from __future__ import annotations
from rsyscall._raw import lib, ffi # type: ignore
import os
import select
import typing as t
from dataclasses import dataclass

class BitField:
    def __init__(self, bitval):
        self.bitval = bitval

    def __get__(self, instance, owner) -> bool:
        return bool(instance.raw & self.bitval)

    def __set__(self, instance, value: bool) -> None:
        if value:
            instance.raw |= self.bitval
        else:
            instance.raw &= ~self.bitval

@dataclass
class EpollEventMask:
    raw: int
    in_ = BitField(select.EPOLLIN)
    out = BitField(select.EPOLLOUT)
    rdhup = BitField(select.EPOLLRDHUP) # type: ignore
    pri = BitField(select.EPOLLPRI)
    err = BitField(select.EPOLLERR)
    hup = BitField(select.EPOLLHUP)
    et = BitField(select.EPOLLET)

    @classmethod
    def make(cls, *, in_=False, out=False, rdhup=False, pri=False, err=False, hup=False, et=False) -> 'EpollEventMask':
        ret = cls(0)
        ret.in_ = in_
        ret.out = out
        ret.rdhup = rdhup
        ret.pri = pri
        ret.err = err
        ret.hup = hup
        ret.et = et
        return ret

    def __str__(self) -> None:
        conditions: t.List[str] = []
        if self.in_:
            conditions.append('in')
        if self.out:
            conditions.append('out')
        if self.rdhup:
            conditions.append('rdhup')
        if self.pri:
            conditions.append('pri')
        if self.err:
            conditions.append('err')
        if self.hup:
            conditions.append('hup')
        if self.et:
            conditions.append('et')
        return 'EpollEventMask(' + ','.join(conditions) + ')'

    def __repr__(self) -> None:
        return str(self)

@dataclass
class EpollEvent:
    data: int
    events: EpollEventMask

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct epoll_event const*', (self.events.raw, (self.data,)))))

    @staticmethod
    def from_bytes(data: bytes) -> EpollEvent:
        struct = ffi.cast('struct epoll_event*', ffi.from_buffer(data))
        return EpollEvent(struct.data.u64, EpollEventMask(struct.events))

    @staticmethod
    def bytesize() -> int:
        return ffi.sizeof('struct epoll_event')
