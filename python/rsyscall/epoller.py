from __future__ import annotations
import errno
import os
import math
import rsyscall.near as near
import typing as t
from rsyscall.concurrency import OneAtATime
from rsyscall.memory.ram import RAM
from rsyscall.handle import FileDescriptor, Pointer, WrittenPointer
import trio

from rsyscall.struct import Bytes, Int32
from rsyscall.handle import Sockbuf
from rsyscall.sys.socket import SOCK, SOL, SO, Address, GenericSockaddr, T_addr
from rsyscall.sys.epoll import EpollEvent, EpollEventList, EPOLL, EPOLL_CTL, EpollFlag
from rsyscall.fcntl import O, F

import logging
logger = logging.getLogger(__name__)

__all__ = [
    "EpollCenter",
    "AsyncFileDescriptor",
]

class EpollWaiter:
    def __init__(self, ram: RAM, epfd: FileDescriptor,
                 wait_readable: t.Optional[t.Callable[[], t.Awaitable[None]]]) -> None:
        self.ram = ram
        self.epfd = epfd
        self.wait_readable = wait_readable
        self.activity_fd: t.Optional[FileDescriptor] = None
        # we reserve 0 for the activity fd
        self.activity_fd_data = 0
        self.next_number = 1
        self.number_to_queue: t.Dict[int, trio.abc.SendChannel] = {}
        self.running_wait = OneAtATime()
        # resumability
        self.input_buf: t.Optional[Pointer[EpollEventList]] = None
        self.syscall_response: t.Optional[near.SyscallResponse] = None
        self.valid_events_buf: t.Optional[Pointer[EpollEventList]] = None

    # need to also support removing, I guess!
    def add_and_allocate_number(self, queue: trio.abc.SendChannel) -> int:
        number = self.next_number
        self.next_number += 1
        self.number_to_queue[number] = queue
        return number

    async def update_activity_fd(self, fd: FileDescriptor) -> None:
        if self.activity_fd is not None:
            raise Exception("activity fd already set", self.activity_fd, fd)
        logger.info("setting activity fd for %s to %s", self.epfd, fd)
        await self.epfd.epoll_ctl(EPOLL_CTL.ADD, fd, await self.ram.to_pointer(
            EpollEvent(data=self.activity_fd_data, events=EPOLL.IN)))

    async def do_wait(self) -> None:
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                maxevents = 32
                if self.input_buf is None:
                    self.input_buf = await self.ram.malloc_type(EpollEventList, maxevents * EpollEvent.sizeof())
                if self.syscall_response is None:
                    if self.wait_readable is None:
                        timeout = -1
                    else:
                        timeout = 0
                        await self.wait_readable()
                    self.syscall_response = await self.epfd.task.sysif.submit_syscall(
                        near.SYS.epoll_wait, self.epfd.near, self.input_buf.near, maxevents, timeout)
                if self.valid_events_buf is None:
                    count = await self.syscall_response.receive()
                    self.valid_events_buf, _ = self.input_buf.split(count * EpollEvent.sizeof())
                received_events = await self.valid_events_buf.read()
                self.input_buf = None
                self.valid_events_buf = None
                self.syscall_response = None
                for event in received_events:
                    # TODO would be nice to just send these to a "devnull" queue instead...
                    if event.data != self.activity_fd_data:
                        queue = self.number_to_queue[event.data]
                        queue.send_nowait(event.events)

class EpollCenter:
    "Terribly named class that allows registering fds on epoll, and waiting on them"
    @staticmethod
    async def make(ram: RAM, epfd: FileDescriptor,
                   wait_readable: t.Optional[t.Callable[[], t.Awaitable[None]]],
                   activity_fd: t.Optional[FileDescriptor],
    ) -> EpollCenter:
        waiter = EpollWaiter(ram, epfd, wait_readable)
        center = EpollCenter(waiter, epfd, ram)
        if activity_fd:
            await waiter.update_activity_fd(activity_fd)
        return center

    def __init__(self, epoller: EpollWaiter, epfd: FileDescriptor, ram: RAM) -> None:
        self.epoller = epoller
        self.epfd = epfd
        self.ram = ram

    def inherit(self, ram: RAM) -> EpollCenter:
        return EpollCenter(self.epoller, ram.task.make_fd_handle(self.epfd), ram)

    async def register(self, fd: FileDescriptor, events: EPOLL=None) -> EpolledFileDescriptor:
        if events is None:
            events = EPOLL.NONE
        send, receive = trio.open_memory_channel(math.inf)
        number = self.epoller.add_and_allocate_number(send)
        await self.add(fd, EpollEvent(number, events))
        return EpolledFileDescriptor(self, fd, receive, number)

    async def add(self, fd: FileDescriptor, event: EpollEvent) -> None:
        await self.epfd.epoll_ctl(EPOLL_CTL.ADD, fd, await self.ram.to_pointer(event))

    async def modify(self, fd: FileDescriptor, event: EpollEvent) -> None:
        await self.epfd.epoll_ctl(EPOLL_CTL.MOD, fd, await self.ram.to_pointer(event))

    async def delete(self, fd: FileDescriptor) -> None:
        await self.epfd.epoll_ctl(EPOLL_CTL.DEL, fd)

class EpolledFileDescriptor:
    def __init__(self,
                 epoll_center: EpollCenter,
                 fd: FileDescriptor,
                 queue: trio.abc.ReceiveChannel,
                 number: int) -> None:
        self.epoll_center = epoll_center
        self.fd = fd
        self.queue = queue
        self.number = number
        self.in_epollfd = True

    async def modify(self, events: EPOLL) -> None:
        await self.epoll_center.modify(self.fd, EpollEvent(self.number, events))

    async def wait(self) -> t.List[EPOLL]:
        while True:
            try:
                return [self.queue.receive_nowait()]
            except trio.WouldBlock:
                await self.epoll_center.epoller.do_wait()

    async def aclose(self) -> None:
        if self.in_epollfd:
            # TODO hmm, I guess we need to serialize this removal with calls to epoll?
            await self.epoll_center.delete(self.fd)
            self.in_epollfd = False
        await self.fd.invalidate()

class AsyncFileDescriptor:
    epolled: EpolledFileDescriptor

    @staticmethod
    async def make_handle(epoller: EpollCenter, ram: RAM, fd: FileDescriptor, is_nonblock=False
    ) -> AsyncFileDescriptor:
        if not is_nonblock:
            await fd.fcntl(F.SETFL, O.NONBLOCK)
        epolled = await epoller.register(fd, EPOLL.IN|EPOLL.OUT|EPOLL.RDHUP|EPOLL.PRI|EPOLL.ERR|EPOLL.HUP|EPOLL.ET)
        return AsyncFileDescriptor(epolled, ram, fd)

    def __init__(self, epolled: EpolledFileDescriptor, ram: RAM, handle: FileDescriptor) -> None:
        self.epolled = epolled
        self.ram = ram
        self.handle = handle
        self.running_wait = OneAtATime()
        self.is_readable = False
        self.is_writable = False
        self.read_hangup = False
        self.priority = False
        self.error = False
        self.hangup = False

    async def _wait_once(self):
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                events = await self.epolled.wait()
                for event in events:
                    if event & EPOLL.IN:    self.is_readable = True
                    if event & EPOLL.OUT:   self.is_writable = True
                    if event & EPOLL.RDHUP: self.read_hangup = True
                    if event & EPOLL.PRI:   self.priority = True
                    if event & EPOLL.ERR:   self.error = True
                    if event & EPOLL.HUP:   self.hangup = True

    def could_read(self) -> bool:
        return self.is_readable or self.read_hangup or self.hangup or self.error

    async def read_handle(self, ptr: Pointer) -> t.Tuple[Pointer, Pointer]:
        while True:
            while not self.could_read():
                await self._wait_once()
            try:
                return (await self.handle.read(ptr))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                else:
                    raise

    async def read(self, count: int=4096) -> bytes:
        ptr = await self.ram.malloc_type(Bytes, count)
        valid, _ = await self.read_handle(ptr)
        return await valid.read()

    async def wait_for_rdhup(self) -> None:
        while not (self.read_hangup or self.hangup):
            await self._wait_once()

    async def read_raw(self, sysif: near.SyscallInterface, fd: near.FileDescriptor, pointer: near.Pointer, count: int) -> int:
        while True:
            while not self.could_read():
                await self._wait_once()
            try:
                return (await near.read(sysif, fd, pointer, count))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                else:
                    raise

    async def write_handle(self, to_write: Pointer) -> None:
        while to_write.bytesize() > 0:
            while not (self.is_writable or self.error):
                await self._wait_once()
            try:
                written, to_write = await self.handle.write(to_write)
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    # TODO this is not really quite right if it's possible to concurrently call methods on this object.
                    # we really need to lock while we're making the async call, right? maybe...
                    self.is_writable = False
                else:
                    raise

    async def write(self, buf: bytes) -> None:
        ptr = await self.ram.to_pointer(Bytes(buf))
        await self.write_handle(ptr)

    async def write_raw(self, sysif: near.SyscallInterface, fd: near.FileDescriptor, pointer: near.Pointer, count: int) -> int:
        while True:
            while not (self.is_writable or self.error):
                await self._wait_once()
            try:
                return (await near.write(sysif, fd, pointer, count))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    # TODO this is not really quite right if it's possible to concurrently call methods on this object.
                    # we really need to lock while we're making the async call, right? maybe...
                    self.is_writable = False
                else:
                    raise

    async def accept_handle(self, flags: SOCK, addr: WrittenPointer[Sockbuf[T_addr]]
    ) -> t.Tuple[FileDescriptor, WrittenPointer[Sockbuf[T_addr]]]:
        while True:
            while not (self.is_readable or self.hangup):
                await self._wait_once()
            try:
                return (await self.handle.accept(flags, addr))
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    self.is_readable = False
                else:
                    raise

    async def accept(self, flags: SOCK=SOCK.CLOEXEC) -> t.Tuple[FileDescriptor, Address]:
        written_sockbuf = await self.ram.to_pointer(Sockbuf(await self.ram.malloc_struct(GenericSockaddr)))
        fd, sockbuf = await self.accept_handle(flags, written_sockbuf)
        addr = (await (await sockbuf.read()).buf.read()).parse()
        return fd, addr

    async def accept_as_async(self) -> t.Tuple[AsyncFileDescriptor, Address]:
        connfd, addr = await self.accept(flags=SOCK.CLOEXEC|SOCK.NONBLOCK)
        try:
            aconnfd = await AsyncFileDescriptor.make_handle(
                self.epolled.epoll_center, self.ram, connfd, is_nonblock=True)
            return aconnfd, addr
        except Exception:
            await connfd.close()
            raise

    async def connect(self, addr: T_addr) -> None:
        try:
            await self.handle.connect(await self.ram.to_pointer(addr))
        except OSError as e:
            if e.errno == errno.EINPROGRESS:
                while not self.is_writable:
                    await self._wait_once()
                sockbuf = await self.ram.to_pointer(Sockbuf(await self.ram.malloc_struct(Int32)))
                retbuf = await self.handle.getsockopt(SOL.SOCKET, SO.ERROR, sockbuf)
                err = await (await retbuf.read()).buf.read()
                if err != 0:
                    raise OSError(err, os.strerror(err))
            else:
                raise

    async def aclose(self) -> None:
        await self.epolled.aclose()

