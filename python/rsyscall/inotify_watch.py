from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import StandardTask
from rsyscall.epoller import AsyncFileDescriptor, AsyncReadBuffer
from rsyscall.concurrency import OneAtATime
from rsyscall.near import WatchDescriptor
import os
import rsyscall.handle as handle
import trio
import typing as t
from dataclasses import dataclass, field
import math
import enum
from rsyscall.memory.ram import RAM

from rsyscall.sys.inotify import InotifyFlag, IN, InotifyEvent, InotifyEventList
from rsyscall.limits import NAME_MAX

@dataclass
class Watch:
    inotify: Inotify
    channel: trio.abc.ReceiveChannel
    wd: WatchDescriptor
    removed: bool = False

    async def wait(self) -> t.List[InotifyEvent]:
        if self.removed:
            raise Exception("watch was already removed")
        events: t.List[InotifyEvent] = []
        while True:
            try:
                event = self.channel.receive_nowait()
                print("inotify event", event)
                if event.mask & IN.IGNORED:
                    # the name is a bit confusing - getting IGNORED means this watch was removed
                    self.removed = True
                events.append(event)
            except trio.WouldBlock:
                if len(events) == 0:
                    await self.inotify.do_wait()
                else:
                    return events

    async def wait_until_event(self, mask: IN, name: t.Optional[str]=None) -> InotifyEvent:
        while True:
            events = await self.wait()
            print(events)
            for event in events:
                if event.mask & mask and (event.name == name if name else True):
                    return event

    async def remove(self) -> None:
        self.inotify.remove(self.wd)
        # we'll mark this Watch as removed once we get the IN_IGNORED event;
        # only after that do we know for sure that there are no more events
        # coming for this Watch.


_inotify_read_size = 4096
_inotify_minimum_size_to_read_one_event = (ffi.sizeof('struct inotify_event') + NAME_MAX + 1)
assert _inotify_read_size > _inotify_minimum_size_to_read_one_event

class Inotify:
    def __init__(self, asyncfd: AsyncFileDescriptor, ram: RAM) -> None:
        self.asyncfd = asyncfd
        self.ram = ram
        self.wd_to_channel: t.Dict[WatchDescriptor, trio.abc.SendChannel] = {}
        self.running_wait = OneAtATime()

    # note that if we monitor the same path twice we... might overwrite earlier watches?
    # ugh yeah we will. including if we have multiple links to the same thing. hmm.
    # I guess the unit here is the inode.
    # and we can only have a single watch for an inode.
    @staticmethod
    async def make(stdtask: StandardTask) -> Inotify:
        fd = await stdtask.task.base.inotify_init(InotifyFlag.CLOEXEC|InotifyFlag.NONBLOCK)
        asyncfd = await AsyncFileDescriptor.make_handle(stdtask.epoller, stdtask.ram, fd, is_nonblock=True)
        return Inotify(asyncfd, stdtask.ram)

    async def add(self, path: handle.Path, mask: IN) -> Watch:
        wd = await self.asyncfd.handle.inotify_add_watch(await self.ram.to_pointer(path), mask)
        send, receive = trio.open_memory_channel(math.inf)
        watch = Watch(self, receive, wd)
        # if we wrap, this could overwrite a removed watch that still
        # has events in the inotify queue unknown to us. but as the
        # manpage says, that bug is very unlikely, so the kernel has
        # no mitigation for it; so we won't worry either.
        self.wd_to_channel[wd] = send
        return watch

    async def do_wait(self) -> None:
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                valid, _ = await self.asyncfd.read(await self.ram.malloc_type(InotifyEventList, 4096))
                if valid.bytesize() == 0:
                    raise Exception('got EOF from inotify fd? what?')
                for event in await valid.read():
                    self.wd_to_channel[event.wd].send_nowait(event)

    async def remove(self, wd: WatchDescriptor) -> None:
        await self.asyncfd.handle.inotify_rm_watch(wd)

    async def aclose(self) -> None:
        await self.asyncfd.close()
