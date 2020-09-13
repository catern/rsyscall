"""Filesystem-watching implemented using inotify

Nothing special here, this is just normal inotify usage.

"""
from __future__ import annotations
from dataclasses import dataclass, field
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.concurrency import CoroQueue, trio_op
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
    wd: WatchDescriptor
    pending_events: t.List[InotifyEvent]

    def __init__(self, inotify: Inotify, wd: WatchDescriptor) -> None:
        self.inotify = inotify
        self.wd = wd
        self.pending_events = []
        self.queue = CoroQueue.start(self._run)

    async def _run(self, queue: CoroQueue) -> None:
        waiters: t.List[t.Tuple[None, t.Coroutine]] = []
        while True:
            received = await self.inotify.queue.send_request(self.wd)
            self.pending_events.extend(received)
            waiters.extend(queue.fetch_any())
            if waiters:
                _, to_resume = waiters.pop(0)
                to_send = self.pending_events
                self.pending_events = []
                queue.fill_request(to_resume, outcome.Value(to_send))
            if any(event.mask & IN.IGNORED for event in received):
                # this watch was removed, we won't get any more events.
                break
        for _, waiter in waiters:
            queue.fill_request(waiter, outcome.Error(Exception("watch was removed")))
        waiters = []
        while True:
            _, waiter = await queue.get_one()
            queue.fill_request(waiter, outcome.Error(Exception("watch was removed")))

    async def wait(self) -> t.List[InotifyEvent]:
        "Wait for some events to happen at this inode"
        if self.pending_events:
            ret = self.pending_events
            self.pending_events = []
            return ret
        else:
            return await self.queue.send_request(None)

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

import functools
import outcome

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
        self.queue = CoroQueue.start(self._run)

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

    async def _run(self, queue: CoroQueue) -> None:
        wd_to_cb: t.Dict[WatchDescriptor, t.Coroutine] = {}
        while True:
            valid, rest = await trio_op(functools.partial(self.asyncfd.read, self.buf))
            if valid.size() == 0:
                raise Exception('got EOF from inotify fd? what?')
            events = await trio_op(valid.read)
            results = {}
            for event in events:
                results.setdefault(event.wd, []).append(event)
            for wd, cb in queue.fetch_any():
                wd_to_cb[wd] = cb
            for wd, events in results.items():
                queue.fill_request(wd_to_cb[wd], outcome.Value(events))
                del wd_to_cb[wd]
            self.buf = valid + rest

    async def close(self) -> None:
        "Close this inotify file descriptor."
        await self.asyncfd.close()
