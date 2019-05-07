from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import os
import typing as t
import logging
import abc
import socket
import struct
import enum
import signal
import ipaddress
from rsyscall.far import AddressSpace, FDTable, Pointer
from rsyscall.far import Process, ProcessGroup, FileDescriptor
from rsyscall.handle import Task
import rsyscall.handle
from rsyscall.near import SyscallInterface
from rsyscall.exceptions import RsyscallException, RsyscallHangup
import rsyscall.far
import rsyscall.near

# re-exported
from rsyscall.handle import MemoryGateway

class MemoryTransport(MemoryGateway):
    @abc.abstractmethod
    def inherit(self, task: Task) -> MemoryTransport: ...

class MemoryAbstractor:
    # should we return AllocationInterfaces, or Pointers directly?
    # returning Pointers would be nicer for the user...
    # allocationinterface is more direct and exposes more internals to the user, though...
    # hmMmMmmMmm
    # ah but I can just have to_pointer etc be helpers on the interface, which call the real interface methods.
    # that is optimal

    # oh yeah we don't want to return pointers anyway, because this isn't our exact interface;
    # we want somethign typed
    @abc.abstractmethod
    def to_pointer(self, data: bytes) -> Pointer: ...
    @abc.abstractmethod
    def malloc(self, n: int) -> Pointer: ...
    @abc.abstractmethod
    def read(self, ptr: Pointer) -> bytes: ...
    # these three are good interfaces

local_address_space = AddressSpace(os.getpid())
def to_local_pointer(data: t.Union[bytes, bytearray]) -> Pointer:
    return Pointer(local_address_space, rsyscall.near.Pointer(int(ffi.cast('long', ffi.from_buffer(data)))))
