from __future__ import annotations
from rsyscall.base import Pointer, RsyscallException, RsyscallHangup
from rsyscall.base import T_addr, UnixAddress, PathTooLongError, InetAddress
from dataclasses import dataclass
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import rsyscall.far
import rsyscall.near
import os
import typing as t

# This is like a far pointer plus a segment register.
# It means that, as long as it doesn't throw an exception,
# we should be able to access the object behind this pointer.
# I'll call it... an active pointer.
@dataclass
class FileDescriptor:
    task: rsyscall.far.Task
    far: rsyscall.far.FileDescriptor

    def to_near(self) -> rsyscall.near.FileDescriptor:
        return self.task.to_near_fd(self.far)

    def __str__(self) -> str:
        return f"FD({self.task}, {self.far.fd_table}, {self.far.near.number})"

    async def read(self, buf: rsyscall.far.Pointer, count: int) -> int:
        return (await rsyscall.far.read(self.task, self.far, buf, count))

    async def write(self, buf: rsyscall.far.Pointer, count: int) -> int:
        return (await rsyscall.far.write(self.task, self.far, buf, count))

@dataclass
class Pipe:
    read: FileDescriptor
    write: FileDescriptor

@dataclass
class MemoryMapping:
    task: rsyscall.far.Task
    far: rsyscall.far.MemoryMapping

    async def munmap(self) -> None:
        await rsyscall.far.munmap(self.task, self.far)

