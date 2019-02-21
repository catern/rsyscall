from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import StandardTask, AsyncFileDescriptor, InotifyFile
from rsyscall.io import OneAtATime, AsyncReadBuffer
from rsyscall.near import WatchDescriptor
import os
import rsyscall.memory_abstracted_syscalls as memsys
import rsyscall.handle as handle
import trio
import typing as t
from dataclasses import dataclass, field
import math
import enum

@dataclass
class Event:
    mask: Mask
    cookie: int
    name: t.Optional[str]

@dataclass
class Watch:
    inotify: Inotify
    channel: trio.abc.ReceiveChannel
    wd: WatchDescriptor
    removed: bool = False

    async def wait(self) -> Event:
        if self.removed:
            raise Exception("watch was already removed")
        while True:
            try:
                event = self.channel.receive_nowait()
                if event.mask & Mask.IGNORED:
                    # the name is a bit confusing - getting IGNORED means this watch was removed
                    self.removed = True
                return event
            except trio.WouldBlock:
                await self.inotify.do_wait()

    async def remove(self) -> None:
        self.inotify.remove(self.wd)
        # we'll mark this Watch as removed once we get the IN_IGNORED event;
        # only after that do we know for sure that there are no more events
        # coming for this Watch.

class Inotify:
    def __init__(self, asyncfd: AsyncFileDescriptor[InotifyFile], stdtask: StandardTask) -> None:
        self.asyncfd = asyncfd
        self.stdtask = stdtask
        self.wd_to_channel: t.Dict[WatchDescriptor, trio.abc.SendChannel] = {}
        self.running_wait = OneAtATime()
        self.buffer = AsyncReadBuffer(self.asyncfd)

    # note that if we monitor the same path twice we... might overwrite earlier watches?
    # ugh yeah we will. including if we have multiple links to the same thing. hmm.
    # I guess the unit here is the inode.
    # and we can only have a single watch for an inode.
    @staticmethod
    async def make(stdtask: StandardTask) -> Inotify:
        fd = await stdtask.task.inotify_init(lib.IN_CLOEXEC|lib.IN_NONBLOCK)
        asyncfd = await AsyncFileDescriptor.make(stdtask.epoller, fd, is_nonblock=True)
        return Inotify(asyncfd, stdtask)

    async def add(self, path: handle.Path, mask: Mask) -> Watch:
        wd = await memsys.inotify_add_watch(self.stdtask.task.transport, self.stdtask.task.allocator,
                                            self.asyncfd.underlying.handle, path, mask)
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
                struct = await self.buffer.read_cffi('struct inotify_event')
                if struct.len > 0:
                    name_bytes = await self.buffer.read_length(struct.len)
                    if name_bytes is not None:
                        name: t.Optional[str] = os.fsdecode(name_bytes)
                    else:
                        raise Exception('got EOF from inotify fd? what?')
                else:
                    name = None
                wd = WatchDescriptor(struct.wd)
                event = Event(Mask(struct.mask), struct.cookie, name)
                self.wd_to_channel[wd].send_nowait(event)

    async def remove(self, wd: WatchDescriptor) -> None:
        await self.asyncfd.underlying.handle.inotify_rm_watch(wd)

class Mask(enum.IntFlag):
    # possible events, specified in inotify_add_watch and returned in struct inotify_event
    ACCESS = lib.IN_ACCESS
    ATTRIB = lib.IN_ATTRIB
    CLOSE_WRITE = lib.IN_CLOSE_WRITE
    CLOSE_NOWRITE = lib.IN_CLOSE_NOWRITE
    CREATE = lib.IN_CREATE
    DELETE = lib.IN_DELETE
    DELETE_SELF = lib.IN_DELETE_SELF
    MODIFY = lib.IN_MODIFY
    MOVE_SELF = lib.IN_MOVE_SELF
    MOVED_FROM = lib.IN_MOVED_FROM
    MOVED_TO = lib.IN_MOVED_TO
    OPEN = lib.IN_OPEN
    # additional options to inotify_add_watch
    DONT_FOLLOW = lib.IN_DONT_FOLLOW
    EXCL_UNLINK = lib.IN_EXCL_UNLINK
    MASK_ADD = lib.IN_MASK_ADD
    ONESHOT = lib.IN_ONESHOT
    ONLYDIR = lib.IN_ONLYDIR
    # additional bits returned in struct inotify_event 
    IGNORED = lib.IN_IGNORED
    ISDIR = lib.IN_ISDIR
    Q_OVERFLOW = lib.IN_Q_OVERFLOW
    UNMOUNT = lib.IN_UNMOUNT

# let's just have the mask have everything in it, whatever

# so I could just duplicate the list in both.
# but...
# semantically, it's a list of event flags,
# plus some others.
# so actually, we can just store it as a tuple, that's fine

# blaaaaaaaaaaaaaaaaaaah
# let's just enumerate all the flags?
# well what if I want to iterate over the set events tho
# well um
# i guess it could be multiple event types
