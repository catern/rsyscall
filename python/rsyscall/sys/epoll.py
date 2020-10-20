"`#include <sys/epoll.h>`"
from __future__ import annotations
from rsyscall._raw import lib, ffi # type: ignore
from rsyscall.struct import Struct, Serializable
import enum
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
    IN = lib.EPOLLIN
    OUT = lib.EPOLLOUT
    RDHUP = lib.EPOLLRDHUP # type: ignore
    PRI = lib.EPOLLPRI
    ERR = lib.EPOLLERR
    HUP = lib.EPOLLHUP
    # options
    ET = lib.EPOLLET

    def __iter__(self) -> t.Iterator[EPOLL]:
        for flag in EPOLL:
            if self & flag:
                yield flag

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

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask
from rsyscall.handle.pointer import Pointer, WrittenPointer, ReadablePointer

T_fd = t.TypeVar('T_fd', bound='EpollFileDescriptor')
class EpollFileDescriptor(BaseFileDescriptor):
    async def epoll_wait(self, events: Pointer[EpollEventList],
                         timeout: int) -> t.Tuple[ReadablePointer[EpollEventList], Pointer]:
        self._validate()
        with events.borrow(self.task):
            maxevents = events.size()//EpollEvent.sizeof()
            num = await _epoll_wait(self.task.sysif, self.near, events.near, maxevents, timeout)
            valid_size = num * EpollEvent.sizeof()
            return events.readable_split(valid_size)

    async def epoll_ctl(self, op: EPOLL_CTL, fd: BaseFileDescriptor,
                        event: t.Optional[WrittenPointer[EpollEvent]]=None) -> None:
        self._validate()
        with fd.borrow(self.task):
            if event is not None:
                event.check_address_space(self.task)
            return (await _epoll_ctl(self.task.sysif, self.near, op, fd.near, event.near if event else None))

class EpollTask(FileDescriptorTask[T_fd]):
    async def epoll_create(self, flags: EpollFlag=EpollFlag.NONE) -> T_fd:
        return self.make_fd_handle(await _epoll_create(self.sysif, flags|EpollFlag.CLOEXEC))

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _epoll_create(sysif: SyscallInterface, flags: EpollFlag) -> near.FileDescriptor:
    return near.FileDescriptor(await sysif.syscall(SYS.epoll_create1, flags))

async def _epoll_ctl(sysif: SyscallInterface, epfd: near.FileDescriptor, op: EPOLL_CTL,
                     fd: near.FileDescriptor, event: t.Optional[near.Address]=None) -> None:
    if event is None:
        event = 0 # type: ignore
    await sysif.syscall(SYS.epoll_ctl, epfd, op, fd, event)

async def _epoll_wait(sysif: SyscallInterface, epfd: near.FileDescriptor,
                      events: near.Address, maxevents: int, timeout: int) -> int:
    return (await sysif.syscall(SYS.epoll_wait, epfd, events, maxevents, timeout))


#### Tests ####
from unittest import TestCase
class TestEpoll(TestCase):
    def test_epoll_event_list(self) -> None:
        initial = EpollEventList([EpollEvent(42, EPOLL.IN|EPOLL.PRI)])
        output = EpollEventList.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
