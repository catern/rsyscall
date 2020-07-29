"""Filesystem-watching implemented using inotify

Nothing special here, this is just normal inotify usage.

"""
from __future__ import annotations
from dataclasses import dataclass, field
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.concurrency import reset, shift
import contextlib
from rsyscall.epoller import AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.memory.ram import RAM
from rsyscall.near.types import WatchDescriptor
from rsyscall.thread import Thread
import enum
import math
import rsyscall.handle as handle
import trio
import typing as t

from rsyscall.sys.inotify import InotifyFlag, IN, InotifyEvent, InotifyEventList
from rsyscall.limits import NAME_MAX

__all__ = [
    'Watch',
    'Inotify',
]

@dataclass
class Watch:
    "An indidivual inode being watched with an Inotify instance"
    inotify: Inotify
    send_channel: trio.abc.SendChannel
    channel: trio.abc.ReceiveChannel
    wd: WatchDescriptor
    removed: bool = False

    async def wait(self) -> t.List[InotifyEvent]:
        "Wait for some events to happen at this inode"
        if self.removed:
            raise Exception("watch was already removed")
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self.inotify._drive_read)
            event = await self.channel.receive()
            nursery.cancel_scope.cancel()
        if event.mask & IN.IGNORED:
            # the name is confusing - getting IN.IGNORED means this watch was removed
            self.removed = True
        return [event]

    async def wait_until_event(self, mask: IN, name: t.Optional[str]=None) -> InotifyEvent:
        """Wait until an event in this mask, and possibly with this name, happens

        Discards non-matching events.

        """
        while True:
            events = await self.wait()
            for event in events:
                if event.mask & mask and (event.name == name if name else True):
                    return event

    async def remove(self) -> None:
        "Remove this watch from inotify"
        await self.inotify.asyncfd.handle.inotify_rm_watch(self.wd)
        # we'll mark this Watch as removed once we get the IN_IGNORED event;
        # only after that do we know for sure that there are no more events
        # coming for this Watch.


_inotify_read_size = 4096
_inotify_minimum_size_to_read_one_event = (ffi.sizeof('struct inotify_event') + NAME_MAX + 1)
assert _inotify_read_size > _inotify_minimum_size_to_read_one_event

class Inotify:
    "An inotify file descriptor, which allows monitoring filesystem paths for events."
    def __init__(self, asyncfd: AsyncFileDescriptor, ram: RAM,
                 buf: Pointer[InotifyEventList],
    ) -> None:
        "Private; use Inotify.make instead."
        self.asyncfd = asyncfd
        self.ram = ram
        self.buf = buf
        self.wd_to_watch: t.Dict[WatchDescriptor, Watch] = {}
        self.read_lock = trio.Lock()
        self.read_coro = None

    @staticmethod
    async def make(thread: Thread) -> Inotify:
        "Create an Inotify file descriptor in `thread`."
        asyncfd = await AsyncFileDescriptor.make(
            thread.epoller, thread.ram, await thread.task.inotify_init(InotifyFlag.NONBLOCK))
        buf = await thread.ram.malloc(InotifyEventList, _inotify_read_size)
        return Inotify(asyncfd, thread.ram, buf)

    async def add(self, path: handle.Path, mask: IN) -> Watch:
        """Start watching a given path for events in the passed mask

        Note that if we monitor the same inode twice (whether at the same path or not),
        we'll return the same Watch object. Not sure how to make this usable.

        """
        wd = await self.asyncfd.handle.inotify_add_watch(await self.ram.ptr(path), mask)
        # if watch descriptors wrap, we could get back a watch descriptor that has been
        # freed and reallocated but for which we haven't yet read the IN.IGNORED event, so
        # we'd return the wrong Watch. but as the manpage says, that bug is very unlikely,
        # so the kernel has no mitigation for it; so we won't worry either.
        try:
            watch = self.wd_to_watch[wd]
        except KeyError:
            send, receive = trio.open_memory_channel(math.inf)
            watch = Watch(self, send, receive, wd)
            self.wd_to_watch[wd] = watch
        return watch

    async def _drive_read(self) -> None:
        async with self.read_lock:
            if self.read_coro is None:
                self.read_coro = self._run_read()
            await reset(self.read_coro)

    async def _run_read(self) -> None:
        @contextlib.asynccontextmanager
        async def suspend_if_cancelled() -> t.AsyncIterator[None]:
            cancels = []
            def handle_cancelled(exn: BaseException) -> t.Optional[BaseException]:
                if isinstance(exn, trio.Cancelled):
                    cancels.append(exn)
                    return None
                else:
                    return exn
            with trio.MultiError.catch(handle_cancelled):
                yield
            if cancels:
                def set_read_coro(coro) -> None:
                    self.read_coro = coro
                    raise trio.MultiError(cancels)
                await shift(set_read_coro)
        while True:
            while True:
                async with suspend_if_cancelled():
                    valid, rest = await self.asyncfd.read(self.buf)
                    break
            if valid.size() == 0:
                raise Exception('got EOF from inotify fd? what?')
            while True:
                async with suspend_if_cancelled():
                    events = await valid.read()
                    break
            for event in events:
                self.wd_to_watch[event.wd].send_channel.send_nowait(event)
                if event.mask & IN.IGNORED:
                    # the name is confusing - getting IN.IGNORED means this watch was removed
                    del self.wd_to_watch[event.wd]
            self.buf = valid + rest


    async def close(self) -> None:
        "Close this inotify file descriptor."
        await self.asyncfd.close()
