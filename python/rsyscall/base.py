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

class MemoryWriter:
    @abc.abstractmethod
    async def write(self, dest: Pointer, data: bytes) -> None: ...
    @abc.abstractmethod
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None: ...

class MemoryReader:
    @abc.abstractmethod
    async def read(self, src: Pointer, n: int) -> bytes: ...
    @abc.abstractmethod
    async def batch_read(self, ops: t.List[t.Tuple[Pointer, int]]) -> t.List[bytes]: ...

class MemoryTransport(MemoryWriter, MemoryReader):
    @abc.abstractmethod
    def inherit(self, task: Task) -> MemoryTransport: ...

local_address_space = AddressSpace(os.getpid())

class InvalidAddressSpaceError(Exception):
    pass

def memcpy(dest: Pointer, src: Pointer, n: int) -> None:
    neardest = local_address_space.to_near(dest)
    nearsrc = local_address_space.to_near(src)
    lib.memcpy(ffi.cast('void*', int(neardest)), ffi.cast('void*', int(nearsrc)), n)

def cffi_to_local_pointer(cffi_object) -> Pointer:
    return Pointer(local_address_space, rsyscall.near.Pointer(int(ffi.cast('long', cffi_object))))

def to_local_pointer(data: bytes) -> Pointer:
    return cffi_to_local_pointer(ffi.from_buffer(data))
