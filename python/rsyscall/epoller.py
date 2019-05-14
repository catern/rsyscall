from __future__ import annotations
from rsyscall._raw import ffi # type: ignore
import errno
import os
import math
import rsyscall.near as near
import typing as t
from rsyscall.concurrency import OneAtATime
from rsyscall.memory.ram import RAM, RAMThread
from rsyscall.handle import FileDescriptor, Pointer, WrittenPointer, Task
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
                 wait_readable: t.Optional[t.Callable[[], t.Awaitable[None]]],
                 timeout: int,
    ) -> None:
        self.ram = ram
        self.epfd = epfd
        self.wait_readable = wait_readable
        self.timeout = timeout

        self.next_number = 0
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

    async def do_wait(self) -> None:
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                maxevents = 32
                if self.input_buf is None:
                    self.input_buf = await self.ram.malloc_type(EpollEventList, maxevents * EpollEvent.sizeof())
                if self.syscall_response is None:
                    if self.wait_readable:
                        await self.wait_readable()
                    self.syscall_response = await self.epfd.task.sysif.submit_syscall(
                        near.SYS.epoll_wait, self.epfd.near, self.input_buf.near, maxevents, self.timeout)
                if self.valid_events_buf is None:
                    count = await self.syscall_response.receive()
                    self.valid_events_buf, _ = self.input_buf.split(count * EpollEvent.sizeof())
                received_events = await self.valid_events_buf.read()
                self.input_buf = None
                self.valid_events_buf = None
                self.syscall_response = None
                for event in received_events:
                    queue = self.number_to_queue[event.data]
                    queue.send_nowait(event.events)

class EpollCenter:
    "Terribly named class that allows registering fds on epoll, and waiting on them"
    @staticmethod
    def make_subsidiary(ram: RAM, epfd: FileDescriptor, wait_readable: t.Callable[[], t.Awaitable[None]]) -> EpollCenter:
        center = EpollCenter(EpollWaiter(ram, epfd, wait_readable, 0), ram, epfd)
        return center

    @staticmethod
    async def make_root(ram: RAM, task: Task) -> EpollCenter:
        activity_fd = task.sysif.get_activity_fd()
        if activity_fd is None:
            raise Exception("can't make a root epoll center if we don't have an activity_fd to monitor")
        epfd = await task.epoll_create(EpollFlag.CLOEXEC)
        center = EpollCenter(EpollWaiter(ram, epfd, None, -1), ram, epfd)
        # TODO where should we store this, so that we don't deregister the activity_fd?
        epolled = await center.register(
            activity_fd, EPOLL.IN|EPOLL.OUT|EPOLL.RDHUP|EPOLL.PRI|EPOLL.ERR|EPOLL.HUP|EPOLL.ET)
        return center

    def __init__(self, epoller: EpollWaiter, ram: RAM, epfd: FileDescriptor) -> None:
        self.epoller = epoller
        self.ram = ram
        self.epfd = epfd

    def inherit(self, ram: RAM) -> EpollCenter:
        return EpollCenter(self.epoller, ram, ram.task.make_fd_handle(self.epfd))

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

    async def read(self, ptr: Pointer) -> t.Tuple[Pointer, Pointer]:
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

    async def read_some_bytes(self, count: int=4096) -> bytes:
        ptr = await self.ram.malloc_type(Bytes, count)
        valid, _ = await self.read(ptr)
        return await valid.read()

    async def wait_for_rdhup(self) -> None:
        while not (self.read_hangup or self.hangup):
            await self._wait_once()

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

    async def write_all_bytes(self, buf: bytes) -> None:
        ptr = await self.ram.to_pointer(Bytes(buf))
        await self.write_handle(ptr)

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

    async def bind(self, addr: T_addr) -> None:
        await self.handle.bind(await self.ram.to_pointer(addr))

    async def connect_ptr(self, addr: WrittenPointer[Address]) -> None:
        try:
            await self.handle.connect(addr)
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

    async def connect(self, addr: T_addr) -> None:
        await self.connect_ptr(await self.ram.to_pointer(addr))

    async def aclose(self) -> None:
        await self.close()

    async def close(self) -> None:
        await self.epolled.aclose()

class EOFException(Exception):
    pass

class AsyncReadBuffer:
    def __init__(self, fd: AsyncFileDescriptor) -> None:
        self.fd = fd
        self.buf = b""

    async def _read(self) -> t.Optional[bytes]:
        data = await self.fd.read_some_bytes()
        if len(data) == 0:
            if len(self.buf) != 0:
                raise EOFException("got EOF while we still hold unhandled buffered data")
            else:
                return None
        else:
            return data

    async def read_length(self, length: int) -> t.Optional[bytes]:
        while len(self.buf) < length:
            data = await self._read()
            if data is None:
                return None
            self.buf += data
        section = self.buf[:length]
        self.buf = self.buf[length:]
        return section

    async def read_cffi(self, name: str) -> t.Any:
        size = ffi.sizeof(name)
        data = await self.read_length(size)
        if data is None:
            raise EOFException("got EOF while expecting to read a", name)
        nameptr = name + '*'
        dest = ffi.new(nameptr)
        # ffi.cast drops the reference to the backing buffer, so we have to copy it
        src = ffi.cast(nameptr, ffi.from_buffer(data))
        ffi.memmove(dest, src, size)
        return dest[0]

    async def read_length_prefixed_string(self) -> bytes:
        elem_size = await self.read_cffi('size_t')
        elem = await self.read_length(elem_size)
        if elem is None:
            raise EOFException("got EOF while expecting to read environment element of length", elem_size)
        return elem

    async def read_length_prefixed_array(self, length: int) -> t.List[bytes]:
        ret: t.List[bytes] = []
        for _ in range(length):
            ret.append(await self.read_length_prefixed_string())
        return ret

    async def read_envp(self, length: int) -> t.Dict[bytes, bytes]:
        raw = await self.read_length_prefixed_array(length)
        environ: t.Dict[bytes, bytes] = {}
        for elem in raw:
            # if someone passes us a malformed environment element without =,
            # we'll just break, whatever
            key, val = elem.split(b"=", 1)
            environ[key] = val
        return environ

    async def read_until_delimiter(self, delim: bytes) -> t.Optional[bytes]:
        while True:
            try:
                i = self.buf.index(delim)
            except ValueError:
                pass
            else:
                section = self.buf[:i]
                # skip the delimiter
                self.buf = self.buf[i+1:]
                return section
            # buf contains no copies of "delim", gotta read some more data
            data = await self._read()
            if data is None:
                return None
            self.buf += data

    async def read_line(self) -> t.Optional[bytes]:
        return (await self.read_until_delimiter(b"\n"))

    async def read_keyval(self) -> t.Optional[t.Tuple[bytes, bytes]]:
        keyval = await self.read_line()
        if keyval is None:
            return None
        key, val = keyval.split(b"=", 1)
        return key, val

    async def read_known_keyval(self, expected_key: bytes) -> bytes:
        keyval = await self.read_keyval()
        if keyval is None:
            raise EOFException("expected key value pair with key", expected_key, "but got EOF instead")
        key, val = keyval
        if key != expected_key:
            raise EOFException("expected key", expected_key, "but got", key)
        return val

    async def read_known_int(self, expected_key: bytes) -> int:
        return int(await self.read_known_keyval(expected_key))

    async def read_known_fd(self, expected_key: bytes) -> near.FileDescriptor:
        return near.FileDescriptor(await self.read_known_int(expected_key))

    async def read_netstring(self) -> t.Optional[bytes]:
        length_bytes = await self.read_until_delimiter(b':')
        if length_bytes is None:
            return None
        length = int(length_bytes)
        data = await self.read_length(length)
        if data is None:
            raise EOFException("hangup before netstring data")
        comma = await self.read_length(1)        
        if comma is None:
            raise EOFException("hangup before comma at end of netstring")
        if comma != b",":
            raise Exception("bad netstring delimiter", comma)
        return data

class EpollThread(RAMThread):
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 epoller: EpollCenter,
    ) -> None:
        super().__init__(task, ram)
        self.epoller = epoller

    async def make_afd(self, fd: FileDescriptor, nonblock: bool=False) -> AsyncFileDescriptor:
        return await AsyncFileDescriptor.make_handle(self.epoller, self.ram, fd, is_nonblock=nonblock)
