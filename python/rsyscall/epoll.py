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

@dataclass
class EpollEvent:
    data: int
    events: EpollEventMask

    def to_bytes(self) -> bytes:
        return ffi.new('struct epoll_event const*', (self.events.raw, (self.data,)))
