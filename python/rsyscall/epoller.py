"""Non-blocking IO operations implemented using epoll.

We use epoll in edge-triggered mode. Our usage is relatively
straightforward, but there are a few quirks.


--------------------------------------------------------------------------------

To avoid blocking a thread in a call to epoll_wait when there is more
work to be done, there are two options:

1. We can register the epollfd on some higher event loop, and instead
of blocking in epoll_wait, just wait until that event loop tells us
there are events to be read. This is the typical way to use most file
descriptors in a non-blocking way, just applied to an epollfd.

2. Or, we can ensure that all possible pending work is registered on
our epollfd; anything that might want to do some work needs to
register a file descriptor that is readable/writable/etc on our
epollfd.  This is the typical requirement that most event loops place
on the rest of the program.

In an ideal world, we would do both with every epoll instance.
Whenever a new epoll E is created, we would register E on all the
other event loops; and we would register all the other event loops on
E. Then we could freely block in either E or any other event loop, and
not miss any events. We could have multiple event loops in our process
without pain.

Unfortunately, this would necessitate a cycle in epoll registrations
(i.e. an epoll A registered on an epoll B which is itself registered
on epoll A). This would necessitate breaking the cycle each time
epoll_wait is called, which could be non-trivially expensive, and
Linux doesn't want to do that.

So instead, to prevent cycles, we need to use only one of these two
approaches at any one time; at any one time, we'll have a single
"root" event loop which uses approach 2 and can make blocking calls to
epoll_wait; and the other event loops will be "subsidiary", using
approach 1, and delegating their blocking to the root event loop.
Then we can still have multiple event loops in our process.

These two approaches to making an Epoller are implemented in the
"make_subsidiary" (1) and "make_root" (2) classmethods of Epoller.

We would rather go with 2 - the only one allowed to block in our
threads should be us. Unfortunately, most event loop libraries don't
expose a way to function as a subsidiary event loop.  So in the case
of threads which need to interoperate with another event loop, we are
forced into 1.

In other cases, there is no other event loop, so we must go with 2.
We must take care to satisfy the requirements of 2: Anything that
wants to perform work should cause a wakeup on our epollfd.

The only case where we use 1 is when running on the local Python
thread.  There, we use the trio async library; and trio does not
expose its epollfd such that we could use approach 2. Instead, we call
trio's wait_readable method on the epollfd instead of blocking in
epoll_wait.

On every thread other than the local Python thread, we use approach
2. At the moment, the only other source of work that is present in
every thread is the file descriptor from which the rsyscall server
reads incoming syscalls. So that other syscalls will not be blocked by
our calls to epoll_wait, we register that file descriptor (exposed in
SyscallInterface as the "activity fd") on our epollfd. In this way, if
a new syscall is received in the thread while already in a call to
epoll_wait, the epoll_wait will wake up so that the rsyscall server
can read and perform the unrelated syscalls.

We could straightforwardly support a mode for an Epoller to be
registered on another of our Epollers; but we haven't done this
because it's not really useful.


--------------------------------------------------------------------------------

"""
from __future__ import annotations
from dneio import RequestQueue, Continuation, reset
from rsyscall._raw import ffi # type: ignore
import collections
import errno
import os
import math
import typing as t
from rsyscall.near.sysif import SyscallError
from rsyscall.memory.ram import RAM
from rsyscall.handle import FileDescriptor, Pointer, WrittenPointer, Task
from dataclasses import dataclass
from rsyscall.struct import Int32, T_fixed_size
from rsyscall.sys.syscall import SYS
from rsyscall.sys.socket import SOCK, SOL, SO, Sockaddr, SockaddrStorage, T_sockaddr, Sockbuf
from rsyscall.sys.epoll import EpollEvent, EpollEventList, EPOLL, EPOLL_CTL, EpollFlag
from rsyscall.fcntl import O, F

import logging
logger = logging.getLogger(__name__)

__all__ = [
    "Epoller",
    "EpolledFileDescriptor",
    "AsyncFileDescriptor",
    "AsyncReadBuffer",
]

class RemovedFromEpollError(Exception):
    pass

class EpollWaiter:
    """The core class which reads events from the epollfd and dispatches them.

    Many threads may have a copy of our epollfd, and register fds on it. To actually wait
    on this epollfd and pull events from it is the responsibility of this class. By
    inheriting the epollfd to many threads for registration purposes, but centralizing the
    actual epoll_wait calls in this shared class, our usage of epoll becomes more
    efficient.

    """
    def __init__(self, ram: RAM, epfd: FileDescriptor,
                 wait_readable: t.Optional[t.Callable[[], t.Awaitable[None]]],
                 timeout: int,
    ) -> None:
        "To make this, use one of the constructor methods of Epoller: make_subsidiary or make_root"
        self.ram = ram
        self.epfd = epfd
        self.wait_readable = wait_readable
        self.timeout = timeout

        self.used_numbers: t.Set[int] = set()
        self.pending_remove: t.Set[int] = set()
        self.queue = RequestQueue[int, EPOLL]()
        reset(self._run())

    def allocate_number(self, request: int) -> int:
        """Add a callback which will be called on EpollEvents with data == returned number.

        We can then add the returned number to the epollfd with some file descriptor and
        mask.

        This is not the user-interface for epoll. That's the register method on Epoller.

        """
        number = request
        # this is amusingly horrible, but it provides a useful feature:
        # the number in epoll usually matches the fd number.
        while number in self.used_numbers:
            number += 1000
        self.used_numbers.add(number)
        return number

    def remove_number_after_next_epoll_wait(self, number: int) -> None:
        """Remove the callback for this number after the next time we call epoll_wait.

        We don't want to remove it immediately, since even if this
        number was just removed, we might still get an event for it if
        an epoll_wait call was in progress.
        """
        self.pending_remove.add(number)

    async def _run(self) -> None:
        input_buf: Pointer = await self.ram.malloc(EpollEventList, 32 * EpollEvent.sizeof())
        number_to_cb: t.Dict[int, Continuation[EPOLL]] = {}
        registered_activity_fd: t.Optional[FileDescriptor] = None
        while True:
            if self.wait_readable:
                await self.wait_readable()
            activity_fd = self.epfd.task.sysif.get_activity_fd()
            if activity_fd and (registered_activity_fd is not activity_fd):
                # the activity fd changed, we need to register the new one
                if registered_activity_fd:
                    # delete the old registered activity fd
                    await self.epfd.epoll_ctl(EPOLL_CTL.DEL, registered_activity_fd)
                activity_fd_number = self.allocate_number(int(activity_fd))
                # start up a coroutine to consume events from the activity_fd
                async def devnull(activity_fd_number=activity_fd_number):
                    while True:
                        await self.queue.request(activity_fd_number)
                reset(devnull())
                await self.epfd.epoll_ctl(EPOLL_CTL.ADD, activity_fd, await self.ram.ptr(
                    EpollEvent(activity_fd_number,
                               # not edge triggered; we don't want to block if there's
                               # anything that can be read.
                               EPOLL.IN|EPOLL.RDHUP|EPOLL.PRI|EPOLL.ERR|EPOLL.HUP)))
                registered_activity_fd = activity_fd
            try:
                valid_events_buf, rest = await self.epfd.epoll_wait(input_buf, self.timeout)
                received_events = await valid_events_buf.read()
            except Exception as wait_error:
                final_exn = wait_error
                break
            input_buf = valid_events_buf + rest
            for num, cb in self.queue.fetch_any():
                number_to_cb[num] = cb
            for event in received_events:
                number_to_cb[event.data].send(event.events)
                del number_to_cb[event.data]
            for num, cb in self.queue.fetch_any():
                number_to_cb[num] = cb
            for number in list(self.pending_remove):
                number_to_cb[number].throw(RemovedFromEpollError())
                del number_to_cb[number]
                self.pending_remove.remove(number)
        self.queue.close(final_exn)

class Epoller:
    "Terribly named class that allows registering fds on epoll, and waiting on them."
    @staticmethod
    def make_subsidiary(ram: RAM, epfd: FileDescriptor, wait_readable: t.Callable[[], t.Awaitable[None]]) -> Epoller:
        """Make a subsidiary epoller, as described in the module docstring.

        We delegate responsibility for blocking to wait for new events to some other
        component. We call the passed-in wait_readable function to block for new events.

        """
        center = Epoller(EpollWaiter(ram, epfd, wait_readable, 0), ram, epfd)
        return center

    @staticmethod
    async def make_root(ram: RAM, task: Task) -> Epoller:
        """Make a root epoller, as described in the module docstring.

        We take responsibility for blocking to wait for new events for every other
        component in this thread. We pull the activity_fd from the SyscallInterface and
        register it on our epollfd. The activity_fd is readable whenever some other
        component in the thread wants to work on the thread.

        """
        epfd = await task.epoll_create()
        center = Epoller(EpollWaiter(ram, epfd, None, -1), ram, epfd)
        return center

    def __init__(self, epoll_waiter: EpollWaiter, ram: RAM, epfd: FileDescriptor) -> None:
        "Don't construct directly; use one of the constructor methods, make_subsidiary or make_root."
        self.epoll_waiter = epoll_waiter
        self.ram = ram
        self.epfd = epfd

    def inherit(self, ram: RAM) -> Epoller:
        """Make a new Epoller which shares the same EpollWaiter class.

        We inherit the epollfd to a new task for the purpose of registering new fds on it;
        but we share the class and task which actually calls epoll_wait.

        """
        return Epoller(self.epoll_waiter, ram, self.epfd.inherit(ram.task))

    async def register(self, fd: FileDescriptor, events: EPOLL) -> EpolledFileDescriptor:
        """Register a file descriptor on this epollfd, for the given events, calling the passed callback.

        The return value can be used to wait for callback calls, modify the events
        registered for this file descriptor, and delete the file descriptor from this
        epollfd.

        """
        number = self.epoll_waiter.allocate_number(int(fd.near))
        efd = EpolledFileDescriptor(self, fd, number)
        await self.epfd.epoll_ctl(EPOLL_CTL.ADD, fd, await self.ram.ptr(EpollEvent(number, events)))
        return efd

class EpolledFileDescriptor:
    """Representation of a file descriptor registered on an epollfd.

    We have to keep around a reference to the file descriptor to perform
    EPOLL_CTL.DEL. This is a bit annoying, but whatever.

    """
    def __init__(self,
                 epoller: Epoller,
                 fd: FileDescriptor,
                 number: int,
    ) -> None:
        self.epoller = epoller
        self.fd = fd
        # TODO, we should copy this so it can't be closed out from under us
        # self.fd = fd.copy()
        self.number = number
        # We optimistically assume that the FD is ready for reading/writing immediately,
        # by setting our initial status to EPOLL.OUT|EPOLL.IN.
        # This has two benefits:
        # 1. Performance improves on our test suite and in many real-world cases, and
        # 2. More critically, if a user erroneously tries to read or write an FD which
        #    will never receive an EPOLL.OUT or EPOLL.IN because it doesn't support
        #    reading/writing, we'll fail immediately instead of blocking forever.
        self.status = FDStatus(EPOLL.OUT|EPOLL.IN)
        self.in_epollfd = True
        self.queue = RequestQueue[EPOLL, None]()
        self.total_events: t.Counter[EPOLL] = collections.Counter()
        self.consumed_events: t.Dict[EPOLL, int] = {flag: 0 for flag in EPOLL}
        reset(self._run())

    def __str__(self) -> str:
        return f"EpolledFileDescriptor({self.fd.near}, {self.number}, {self.status})"

    async def modify(self, events: EPOLL) -> None:
        "Change the EPOLL flags that this fd is registered with."
        await self.epoller.epfd.epoll_ctl(
            EPOLL_CTL.MOD, self.fd, await self.epoller.ram.ptr(EpollEvent(self.number, events)))

    async def delete(self) -> None:
        "Delete this fd from the epollfd."
        if not self.in_epollfd:
            raise Exception("already deleted from epollfd")
        await self.epoller.epfd.epoll_ctl(EPOLL_CTL.DEL, self.fd)
        self.epoller.epoll_waiter.remove_number_after_next_epoll_wait(self.number)
        self.in_epollfd = False

    async def _run(self) -> None:
        waiters: t.Dict[EPOLL, t.List[t.Tuple[EPOLL, Continuation[None]]]] = {flag: [] for flag in EPOLL}
        while True:
            try:
                ev = await self.epoller.epoll_waiter.queue.request(self.number)
            except Exception as e:
                final_exn = e
                break
            self.total_events.update(ev)
            self.status.posedge(ev)
            for val, coro in self.queue.fetch_any():
                for flag in val:
                    waiters[flag].append((val, coro))
            for flag in ev:
                to_resume = waiters[flag]
                for val, cb in list(to_resume):
                    # remove the cb from other lists it's on; cool scope there, Python
                    for waiting_flag in val:
                        waiters[waiting_flag].remove((val, cb))
                    cb.send(None)
        self.queue.close(final_exn)

    async def wait_for(self, flags: EPOLL) -> None:
        "Call epoll_wait until at least one of the passed flags is set in our status."
        if (not (self.status.mask & flags)
            and not any(self.total_events[flag] - self.consumed_events[flag] > 0
                        for flag in flags)):
            return await self.queue.request(flags)

    def consume(self, events: t.Dict[EPOLL, int]) -> None:
        """The information from these events is outdated; discard them

        Each syscall gives us information about some kinds of events, and information from
        events from epoll_wait calls before that syscall are obsoleted by this more
        up-to-date information.

        So, we call `get_current_events` before each syscall, for the set of flags that
        that syscall will inform us about. Then, after the syscall, we call `consume`, to
        indicate that the information from those events is now obsolete.

        We can't consume the events until after the syscall is done, because we want to
        allow others to optimistically perform syscalls based on these epoll events; not
        consuming the events immediately also makes us tolerate being canceled without
        performing the syscall.

        Only the events received before the syscall are known to be obsolete; events
        received during or after this syscall need to be preserved until more syscalls are
        made, to prevent deadlocks.

        The reason we need this somewhat complicated edifice is because our calls to
        epoll_wait are not synchronized with our system calls on individual file
        descriptors; calls to epoll_wait and fd system calls can happen in different
        threads and can be arbitrarily reordered relative to each other.

        Note, however, that system calls made from an individual `AsyncFileDescriptor`
        instance *are* synchronized relative to each other; those system calls are made in
        a single thread, so the system calls return in order thanks to `dneio`. This
        allows us to safely immediately call `FDStatus.negedge`/`FDStatus.posedge` after a
        system call.

        TODO if we have multiple concurrently-used `AsyncFileDescriptor` instances,
        though, they aren't synchronized, so we need to be a little more careful...

        """
        self.consumed_events.update(((flag, max(self.consumed_events[flag], count))
                                     for flag, count in events.items()))

    def get_current_events(self, flags: EPOLL) -> t.Dict[EPOLL, int]:
        "Get the current set of events from epoll_wait for these flags, for use with consume."
        return {flag: self.total_events[flag] for flag in flags}

@dataclass
class FDStatus:
    """Tracks the IO status of a file as an EPOLL mask.

    With edge-triggered epoll, we can track whether a file is ready for a given IO in
    userspace.

    Edge-triggered epoll sends us a stream of posedges for each tracked file: Each time we get
    an EPOLLET event, it means that the file is ready for the IO operations corresponding
    to the bits set in the event. We track this by just or-ing in the event's mask into
    FDStatus's mask.

    We receive negedges by getting EAGAINs (or similar equivalents) when performing
    operations on file descriptors. Each one tells us that the file is not ready for some
    specific IO operation. We track this by translating it into the corresponding EPOLL
    flag and unsetting it in FDStatus's mask.

    By following this discipline and getting every event, we know for sure at any time
    whether a file *might* be ready for IO, or if instead it's safe to block in a call to
    epoll_wait to wait for the file to be ready.

    Dropping a negedge decreases our efficiency, but is harmless, since we'll just get an
    EAGAIN the next time. Dropping a posedge is very bad and means we will deadlock.

    epoll seems to not send us a posedge if we could already know that the file descriptor
    is readable. So, for example, if we directly read an fd and we haven't already gotten
    a posedge for it, and we get a full buffer of data, then we won't get a posedge for it
    from epoll. This would cause various problems, including deadlocks if multiple threads
    were trying to read from the fd and one was blocked in epoll_wait, waiting for the
    posedge.

    Therefore, if you optimistically read an fd before getting a posedge from epoll, and
    you successfully read some data, make sure to treat that as a posedge for EPOLL.IN.
    Likewise with write and EPOLL.OUT, and any other event and the appropriate EPOLL bit.

    """
    mask: EPOLL

    def posedge(self, event: EPOLL) -> None:
        self.mask |= event

    def negedge(self, event: EPOLL) -> None:
        self.mask &= ~event

class AsyncFileDescriptor:
    """A file descriptor on which IO can be performed without blocking the thread.

    Also comes with helpful methods `AsyncFileDescriptor.write_all_bytes` and
    `AsyncFileDescriptor.read_some_bytes` to abstract over memory allocation.

    We always wait for a posedge to come back from epoll before trying to read. This is
    not necessarily too pessimistic, because as soon as we have a single posedge, we will
    keep reading in a loop, as long as data keeps coming through.

    """
    @staticmethod
    async def make(epoller: Epoller, ram: RAM, fd: FileDescriptor) -> AsyncFileDescriptor:
        """Make an AsyncFileDescriptor; make sure to call this with only O.NONBLOCK file descriptors.

        It won't actually break anything if this is called with file descriptors not in
        NONBLOCK mode; it just means that they'll block when we go to read, which is
        probably not what the user wants.

        """
        epolled = await epoller.register(
            fd, EPOLL.IN|EPOLL.OUT|EPOLL.RDHUP|EPOLL.PRI|EPOLL.ERR|EPOLL.HUP|EPOLL.ET,
        )
        return AsyncFileDescriptor(ram, fd, epolled)

    def __init__(self, ram: RAM, handle: FileDescriptor,
                 epolled: EpolledFileDescriptor,
    ) -> None:
        "Don't construct directly; use the AsyncFileDescriptor.make constructor instead."
        self.ram = ram
        self.handle = handle
        "The underlying FileDescriptor for this AFD, used for all system calls"
        self.epolled = epolled

    def __str__(self) -> str:
        return f"AsyncFileDescriptor({self.epolled})"

    async def make_new_afd(self, fd: FileDescriptor) -> AsyncFileDescriptor:
        """Use the Epoller and RAM in this AsyncFD to make a new `AsyncFileDescriptor` for `fd`

        Make sure that `fd` is already in non-blocking mode;
        such as by accepting it with the `SOCK.NONBLOCK` flag.

        This doesn't steal any resources from the original AFD; it's just a convenience method,
        most useful when calling accept() and wanting to create new AFDs out of the resulting FDs.

        """
        return await AsyncFileDescriptor.make(self.epolled.epoller, self.ram, fd)

    async def wait_for_rdhup(self) -> None:
        "Call epoll_wait until this file descriptor has a hangup."
        await self.epolled.wait_for(EPOLL.RDHUP|EPOLL.HUP)

    async def read(self, ptr: Pointer) -> t.Tuple[Pointer, Pointer]:
        "Call `FileDescriptor.read` without blocking the thread."
        while True:
            await self.epolled.wait_for(EPOLL.IN|EPOLL.RDHUP|EPOLL.HUP|EPOLL.ERR)
            current_events = self.epolled.get_current_events(EPOLL.IN|EPOLL.RDHUP|EPOLL.HUP|EPOLL.ERR)
            try:
                return (await self.handle.read(ptr))
            except OSError as e:
                self.epolled.consume(current_events)
                if e.errno == errno.EAGAIN:
                    self.epolled.status.negedge(EPOLL.IN|EPOLL.RDHUP|EPOLL.HUP|EPOLL.ERR)
                else:
                    self.epolled.status.posedge(EPOLL.ERR)
                    raise
            else:
                self.epolled.consume(current_events)
                self.epolled.status.posedge(EPOLL.IN|EPOLL.RDHUP|EPOLL.HUP)

    async def read_some_bytes(self, count: int=4096) -> bytes:
        """Read at most count bytes; possibly less, if we have a partial read.

        This allocates on each call. For some applications, you may want to avoid the cost of
        allocation, by instead allocating a buffer with `Thread.malloc` up front and reusing it
        across multiple calls to `AsyncFileDescriptor.read`.

        """
        ptr = await self.ram.malloc(bytes, count)
        valid, _ = await self.read(ptr)
        return await valid.read()

    async def write(self, buf: Pointer) -> t.Tuple[Pointer, Pointer]:
        """Call `FileDescriptor.write` without blocking the thread.

        Note that this doesn't retry partial writes, which are always a possibility, so you should
        make sure to do that yourself, or use `AsyncFileDescriptor.write_all`.

        """
        while True:
            await self.epolled.wait_for(EPOLL.OUT|EPOLL.ERR)
            current_events = self.epolled.get_current_events(EPOLL.OUT|EPOLL.ERR)
            try:
                return await self.handle.write(buf)
            except OSError as e:
                self.epolled.consume(current_events)
                if e.errno == errno.EAGAIN:
                    self.epolled.status.negedge(EPOLL.OUT|EPOLL.ERR)
                else:
                    self.epolled.status.posedge(EPOLL.ERR)
                    raise
            else:
                self.epolled.consume(current_events)
                self.epolled.status.posedge(EPOLL.OUT)

    async def write_all(self, to_write: Pointer) -> None:
        """Write all of this pointer to the fd, retrying on partial writes until complete.

        You might want to not use this, if you want to react to a partial write in some special way.
        For example, `rsyscall.memory.socket_transport.SocketMemoryTransport` starts a `recv`
        immediately after a partial write, before retrying the write, for increased parallelism.

        """
        while to_write.size() > 0:
            written, to_write = await self.write(to_write)

    async def write_all_bytes(self, buf: bytes) -> None:
        """Write all these bytes to the fd, retrying on partial writes until complete.

        This allocates and performs a store to memory on each call. This is inefficient if you
        already have an initialized pointer for the value, or if you already have an allocated
        buffer that you can use to store the value, which you can also reuse for other values.
        In those cases, you might want to use `AsyncFileDescriptor.write_all`.

        """
        ptr = await self.ram.ptr(buf)
        await self.write_all(ptr)

    @t.overload
    async def accept(self, flags: SOCK=SOCK.NONE) -> FileDescriptor: ...
    @t.overload
    async def accept(self, flags: SOCK, addr: WrittenPointer[Sockbuf[T_sockaddr]]
    ) -> t.Tuple[FileDescriptor, WrittenPointer[Sockbuf[T_sockaddr]]]: ...

    async def accept(self, flags: SOCK=SOCK.NONE, addr: t.Optional[WrittenPointer[Sockbuf[T_sockaddr]]]=None
    ) -> t.Union[FileDescriptor, t.Tuple[FileDescriptor, WrittenPointer[Sockbuf[T_sockaddr]]]]:
        "Call accept without blocking the thread."
        while True:
            await self.epolled.wait_for(EPOLL.IN|EPOLL.HUP|EPOLL.ERR)
            current_events = self.epolled.get_current_events(EPOLL.IN|EPOLL.HUP|EPOLL.ERR)
            try:
                if addr is None:
                    return (await self.handle.accept(flags))
                else:
                    return (await self.handle.accept(flags, addr))
            except OSError as e:
                self.epolled.consume(current_events)
                if e.errno == errno.EAGAIN:
                    self.epolled.status.negedge(EPOLL.IN|EPOLL.HUP|EPOLL.ERR)
                else:
                    self.epolled.status.posedge(EPOLL.HUP|EPOLL.ERR)
                    raise
            else:
                self.epolled.consume(current_events)
                self.epolled.status.posedge(EPOLL.IN)

    async def accept_addr(self, flags: SOCK=SOCK.NONE) -> t.Tuple[FileDescriptor, Sockaddr]:
        "Call accept with a buffer for the address, and return the resulting fd and address."
        written_sockbuf = await self.ram.ptr(Sockbuf(await self.ram.malloc(SockaddrStorage)))
        fd, sockbuf = await self.accept(flags, written_sockbuf)
        addr = (await (await sockbuf.read()).buf.read()).parse()
        return fd, addr

    async def bind(self, addr: WrittenPointer[Sockaddr]) -> None:
        "Call bind; bind already doesn't block the thread."
        await self.handle.bind(addr)

    async def connect(self, addr: WrittenPointer[Sockaddr]) -> None:
        "Call connect without blocking the thread."
        try:
            # Note that an unconnected socket, at least with AF.INET SOCK.STREAM,
            # will have EPOLL.OUT|EPOLL.HUP set when added to epoll, before calling connect.
            current_events = self.epolled.get_current_events(EPOLL.OUT)
            await self.handle.connect(addr)
        except OSError as e:
            self.epolled.consume(current_events)
            self.epolled.status.negedge(EPOLL.OUT)
            if e.errno == errno.EINPROGRESS:
                await self.epolled.wait_for(EPOLL.OUT)
                current_events = self.epolled.get_current_events(EPOLL.OUT)
                sockbuf = await self.ram.ptr(Sockbuf(await self.ram.malloc(Int32)))
                retbuf = await self.handle.getsockopt(SOL.SOCKET, SO.ERROR, sockbuf)
                err = await (await retbuf.read()).buf.read()
                self.epolled.consume(current_events)
                if err == 0:
                    self.epolled.status.posedge(EPOLL.OUT)
                else:
                    self.epolled.status.posedge(EPOLL.ERR)
                    try:
                        raise OSError(err, os.strerror(err))
                    except OSError as exn:
                        exn.filename = self.handle
                        if hasattr(addr, 'value'):
                            exn.filename2 = addr.value
                        raise
            else:
                raise
        else:
            self.epolled.consume(current_events)
            self.epolled.status.posedge(EPOLL.OUT)

    def with_handle(self, fd: FileDescriptor) -> AsyncFileDescriptor:
        """Return a new AFD using this new FD handle for making syscalls.

        This is useful when we want to change what task we're making syscalls in when
        using this AFD.

        """
        return AsyncFileDescriptor(self.ram, fd, self.epolled)

    async def close(self) -> None:
        "Remove this FD from Epoll and invalidate the FD handle."
        await self.epolled.delete()
        await self.handle.invalidate()

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        await self.close()


################################################################################
# Miscellaneous helpers

class AsyncReadBuffer:
    """A buffer for parsing variable-length streaming data.

    When reading data from a stream such as a pipe or TCP connection, data is not
    delivered to us from the kernel in nicely-separated records. We need to rebuffer the
    data so that it can be parsed. That's what this class does; and it provides a few
    helper methods to make it easier to read and parse such streams.

    """
    def __init__(self, fd: AsyncFileDescriptor) -> None:
        self.fd = fd
        self.buf = b""
        self.unread_ptr: t.Optional[Pointer] = None

    async def _read(self) -> bytes:
        "Read some bytes; return None on EOF."
        if self.unread_ptr is None:
            ptr = await self.fd.ram.malloc(bytes, 4096)
            self.unread_ptr, _ = await self.fd.read(ptr)
        if self.unread_ptr.size():
            data = await self.unread_ptr.read()
        else:
            data = b''
        self.unread_ptr = None
        if len(data) == 0:
            raise EOFError
        else:
            return data

    async def read_length(self, length: int) -> bytes:
        "Read exactly this many bytes; raises on EOF."
        while len(self.buf) < length:
            data = await self._read()
            self.buf += data
        section = self.buf[:length]
        self.buf = self.buf[length:]
        return section

    async def read_cffi(self, name: str) -> t.Any:
        "Read, parse, and return this fixed-size cffi type."
        size = ffi.sizeof(name)
        try:
            data = await self.read_length(size)
        except EOFError as e:
            e.args = ("got EOF while expecting to read a", name, "of size", size)
            raise
        nameptr = name + '*'
        dest = ffi.new(nameptr)
        # ffi.cast drops the reference to the backing buffer, so we have to copy it
        src = ffi.cast(nameptr, ffi.from_buffer(data))
        ffi.memmove(dest, src, size)
        return dest[0]

    async def read_struct(self, cls: t.Type[T_fixed_size]) -> T_fixed_size:
        "Read one fixed-size struct from the buffer, or return None if that's not possible"
        size = cls.sizeof()
        try:
            data = await self.read_length(size)
        except EOFError as e:
            e.args = ("got EOF while expecting to read a", cls, "of size", size)
            raise
        return cls.get_serializer(self.fd.handle.task).from_bytes(data)

    async def read_length_prefixed_string(self) -> bytes:
        "Read a bytestring which is prefixed with a 64-bit native-byte-order size."
        elem_size = await self.read_cffi('size_t')
        try:
            elem = await self.read_length(elem_size)
        except EOFError as e:
            e.args = ("got EOF while expecting to read environment element of length", elem_size)
        return elem

    async def read_length_prefixed_array(self, length: int) -> t.List[bytes]:
        "Read an array, prefixed with its size, of bytestrings, each prefixed with their size."
        ret: t.List[bytes] = []
        for _ in range(length):
            ret.append(await self.read_length_prefixed_string())
        return ret

    async def read_envp(self, length: int) -> t.Dict[str, str]:
        """Read a size-prefixed array of size-prefixed bytestrings, with each bytestring containing '=', into a dict.

        This is the format we expect for envp, which is written to us on startup by
        non-child threads.

        We assume that the environment is correctly formed; that is, each element contains
        '='.  If that's not true, we'll throw an exception.  But it would be quite unusual
        to have an incorrectly formed environment variable, so it's not too concerning.

        """
        raw = await self.read_length_prefixed_array(length)
        environ: t.Dict[str, str] = {}
        for elem in raw:
            key, val = elem.split(b"=", 1)
            environ[os.fsdecode(key)] = os.fsdecode(val)
        return environ

    async def read_until_delimiter(self, delim: bytes) -> t.Optional[bytes]:
        "Read and return all bytes until the specified delimiter, stripping the delimiter; on EOF, return None."
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

    async def read_line(self) -> bytes:
        "Read and return a line, stripping the newline character."
        ret = await self.read_until_delimiter(b"\n")
        if ret is None:
            raise EOFError("hangup before reading full line")
        return ret

    async def read_netstring(self) -> bytes:
        "Read a netstring, as defined by DJB."
        length_bytes = await self.read_until_delimiter(b':')
        if length_bytes is None:
            raise EOFError("hangup before reaching colon at end of netstring size")
        length = int(length_bytes)
        try:
            data = await self.read_length(length)
        except EOFError as e:
            e.args = ("hangup before we read netstring data of size", length)
            raise
        try:
            comma = await self.read_length(1)
        except EOFError as e:
            e.args = ("hangup before comma at end of netstring",)
            raise
        if comma != b",":
            raise Exception("bad netstring delimiter", comma)
        return data
