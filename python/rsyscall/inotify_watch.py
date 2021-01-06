"""Filesystem-watching implemented using inotify

Nothing special here, this is just normal inotify usage.

"""
from __future__ import annotations
from dataclasses import dataclass, field
from dneio import RequestQueue, reset, Continuation
from rsyscall import Pointer
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

__all__ = [
    'Watch',
    'Inotify',
]

@dataclass
class Watch:
    "An indidivual inode being watched with an Inotify instance"
    inotify: Inotify
    wd: WatchDescriptor
    pending_events: t.List[InotifyEvent]

    def __init__(self, inotify: Inotify, wd: WatchDescriptor) -> None:
        self.inotify = inotify
        self.wd = wd
        self.pending_events = []
        self.queue = RequestQueue[None, t.List[InotifyEvent]]()
        reset(self._run())

    async def _run(self) -> None:
        waiters: t.List[t.Tuple[None, Continuation[t.List[InotifyEvent]]]] = []
        while True:
            received = await self.inotify.queue.request(self.wd)
            self.pending_events.extend(received)
            waiters.extend(self.queue.fetch_any())
            if waiters:
                _, to_resume = waiters.pop(0)
                to_send = self.pending_events
                self.pending_events = []
                to_resume.send(to_send)
            if any(event.mask & IN.IGNORED for event in received):
                # this watch was removed, we won't get any more events.
                break
        for _, waiter in waiters:
            waiter.throw(Exception("watch was removed"))
        waiters = []
        while True:
            _, waiter = await self.queue.get_one()
            waiter.throw(Exception("watch was removed"))

    async def wait(self) -> t.List[InotifyEvent]:
        "Wait for some events to happen at this inode"
        if self.pending_events:
            ret = self.pending_events
            self.pending_events = []
            return ret
        else:
            return await self.queue.request(None)

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
assert _inotify_read_size > InotifyEvent.MINIMUM_SIZE_TO_READ_ONE_EVENT

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
        self.queue = RequestQueue[WatchDescriptor, t.List[InotifyEvent]]()
        reset(self._run())

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
            watch = Watch(self, wd)
            self.wd_to_watch[wd] = watch
        return watch

    async def _run(self) -> None:
        wd_to_cb: t.Dict[WatchDescriptor, Continuation] = {}
        while True:
            valid, rest = await self.asyncfd.read(self.buf)
            if valid.size() == 0:
                raise Exception('got EOF from inotify fd? what?')
            events = await valid.read()
            results: t.Dict[WatchDescriptor, t.List[InotifyEvent]] = {}
            for event in events:
                results.setdefault(event.wd, []).append(event)
            for wd, cb in self.queue.fetch_any():
                wd_to_cb[wd] = cb
            for wd, events in results.items():
                wd_to_cb[wd].send(events)
                del wd_to_cb[wd]
            self.buf = valid + rest
