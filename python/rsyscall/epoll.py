from rsyscall._raw import lib, ffi # type: ignore
import os
import select
import typing as t

EPOLL_CLOEXEC=lib.EPOLL_CLOEXEC
AT_EMPTY_PATH=lib.AT_EMPTY_PATH
AT_SYMLINK_NOFOLLOW=lib.AT_SYMLINK_NOFOLLOW

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

class EpollEventMask:
    raw: int
    in_ = BitField(select.EPOLLIN)
    out = BitField(select.EPOLLOUT)
    rdhup = BitField(select.EPOLLRDHUP) # type: ignore
    pri = BitField(select.EPOLLPRI)
    err = BitField(select.EPOLLERR)
    hup = BitField(select.EPOLLHUP)
    et = BitField(select.EPOLLET)
    def __init__(self, raw: int) -> None:
        self.raw = raw

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

    def __str__(self) -> str:
        return f"EpollEventMask({self.raw})"

class EpollEvent:
    events: EpollEventMask
    data: int
    def __init__(self, data: int, events: EpollEventMask) -> None:
        self.data = data
        self.events = events

    def __str__(self) -> str:
        return f"EpollEvent({self.data}, {self.events})"

def throw_on_error(ret) -> int:
    if ret < 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err))
    else:
        return ret

def epoll_create(flags: int) -> int:
    return throw_on_error(lib.epoll_create1(flags))

def epoll_ctl(epfd: int, op: int, fd: int, event: EpollEvent) -> None:
    c_event = ffi.new('struct epoll_event const*', (event.events.raw, (event.data,)))
    throw_on_error(lib.epoll_ctl(epfd, op, fd, c_event))

def epoll_ctl_add(epfd: int, fd: int, event: EpollEvent) -> None:
    epoll_ctl(epfd, lib.EPOLL_CTL_ADD, fd, event)

def epoll_ctl_mod(epfd: int, fd: int, event: EpollEvent) -> None:
    epoll_ctl(epfd, lib.EPOLL_CTL_MOD, fd, event)

def epoll_ctl_del(epfd: int, fd: int) -> None:
    throw_on_error(lib.epoll_ctl(epfd, lib.EPOLL_CTL_DEL, fd, ffi.NULL))

def epoll_wait(epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]:
    c_events = ffi.new('struct epoll_event[]', maxevents)
    count = throw_on_error(lib.epoll_wait(epfd, c_events, maxevents, timeout))
    ret = []
    for ev in c_events[0:count]:
        ret.append(EpollEvent(ev.data.u64, EpollEventMask(ev.events)))
    return ret
