from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import Task, Epoller
from rsyscall.near import WatchDescriptor
import typing as t
from dataclasses import dataclass, field
import enum

class Event:
    mask: Mask
    cookie: int
    name: t.Optional[str]

class Watch:
    def __init__(self, inotify: Inotify, wd: WatchDescriptor) -> None:
        self.inotify = inotify
        self.wd = wd
        self.removed = False

    async def wait(self) -> t.List[Event]:
        if self.removed:
            raise Exception("watch was already removed")
        while True:
            try:
                event = self.child_events_channel.receive_nowait()
                if event.mask & Mask.IGNORED:
                    # the name is a bit confusing - getting IGNORED means this watch was removed
                    self.removed = True
                return [event]
            except trio.WouldBlock:
                await self.inotify.do_wait()

    async def remove(self) -> None:
        self.inotify.remove(self.wd)

class Inotify:
    # note that if we monitor the same path twice we... might overwrite earlier watches?
    # ugh yeah we will. including if we have multiple links to the same thing. hmm.
    # I guess the unit here is the inode.
    # and we can only have a single watch for an inode.
    @staticmethod
    async def make(self, task: Task, epoller: Epoller) -> None:
        # make inotify file
        # make asyncfd
        pass

    async def add(self, path: Path, mask: Mask) -> Watch:
        wd = await memsys.inotify_add_watch(self.task.transport, self.task.allocator, self.fd, path, mask)
        send, receive = trio.open_memory_channel(math.inf)
        watch = Watch(self, receive, wd)
        # if we wrap, this could overwrite a removed watch that still
        # has events in the inotify queue unknown to us. but as the
        # manpage says, that bug is very unlikely, so the kernel has
        # no mitigation for it; so we won't worry either.
        self.wd_to_channel[wd] = send

    async def do_wait(self):
        async with self.running_wait.needs_run() as needs_run:
            if needs_run:
                # read on async fd
                data = await self.fd.read()
                pass

    async def remove(self, wd: WatchDescriptor) -> None:
        await self.fd.inotify_remove_watch(wd)

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
