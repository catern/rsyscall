"`#include <sched.h>`"
from __future__ import annotations
from rsyscall._raw import lib, ffi # type: ignore
from rsyscall.struct import Serializable, Serializer, Struct, bits
from dataclasses import dataclass
import enum
import typing as t
import struct
import contextlib
if t.TYPE_CHECKING:
    from rsyscall.handle import Task, Pointer, WrittenPointer, FileDescriptor
    from rsyscall.loader import NativeFunction

__all__ = [
    'CpuSet',
    'Borrowable', 'Stack',
]

class CLONE(enum.IntFlag):
    "The flag argument to clone, unshare, and setns"
    NONE = 0
    ### other flags for clone
    VFORK = lib.CLONE_VFORK
    CHILD_CLEARTID = lib.CLONE_CHILD_CLEARTID
    ### sharing-control
    PARENT = lib.CLONE_PARENT
    VM = lib.CLONE_VM
    SIGHAND = lib.CLONE_SIGHAND
    IO = lib.CLONE_IO
    # valid for unshare
    FILES = lib.CLONE_FILES
    FS = lib.CLONE_FS
    NEWCGROUP = lib.CLONE_NEWCGROUP
    NEWIPC = lib.CLONE_NEWIPC
    NEWNET = lib.CLONE_NEWNET
    NEWNS = lib.CLONE_NEWNS
    NEWPID = lib.CLONE_NEWPID
    NEWUSER = lib.CLONE_NEWUSER
    NEWUTS = lib.CLONE_NEWUTS
    SYSVSEM = lib.CLONE_SYSVSEM


class Borrowable:
    """An interface for objects that can be borrowed.

    This doesn't make much sense in this file, but its primary use is for the
    generic type argument to Stack; we need to be able to borrow all the values
    inside the Stack, without knowing concretely what is inside.

    """
    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None:
        "Borrow this value in this `task` on this `stack`, so that this value is valid while the borrow lives"
        raise NotImplementedError("borrow_with not implemented on", type(self))

T_borrowable = t.TypeVar('T_borrowable', bound=Borrowable)

_address = struct.Struct("Q")

@dataclass
class Stack(Serializable, t.Generic[T_borrowable]):
    """The stack argument to clone

    All rsyscall threads, after executing the clone syscall, immediately call
    the "ret" instruction. Thus, the first value on any stack passed to clone
    must be a function pointer, which ret will pop off and begin executing.

    After that, the stack can hold any arbitrary data which the function can
    use. That data may include rsyscall types, which will be borrowed at clone
    time to ensure they are valid at least for the start of the function's
    execution.

    """
    function: Pointer[NativeFunction]
    data: T_borrowable
    serializer: Serializer[T_borrowable]

    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None:
        stack.enter_context(self.function.borrow(task))
        self.data.borrow_with(stack, task)

    def to_bytes(self) -> bytes:
        return _address.pack(int(self.function.near)) + self.serializer.to_bytes(self.data)

    T_stack = t.TypeVar('T_stack', bound='Stack')
    @classmethod
    def from_bytes(cls: t.Type[T_stack], data: bytes) -> T_stack:
        raise Exception("nay")

class CpuSet(Struct, t.Set[int]):
    """cpu_set_t, as used in sched_setaffinity and sched_getaffinity

    Currently we fix the size of the cpuset at 1024 bits, just like glibc. To
    support systems with more CPUs, we should loosen this fixed-size-ness.

    """
    def to_bytes(self) -> bytes:
        output = [0]*16
        for val in self:
            idx = val // 64
            bit = val % 64
            output[idx] |= 1 << bit
        return bytes(ffi.buffer(ffi.new('cpu_set_t const*', (output,))))

    T = t.TypeVar('T', bound='CpuSet')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('cpu_set_t*', ffi.from_buffer(data))
        ret: t.List[int] = []
        for i, val in enumerate(getattr(struct, '__bits')):
            inc = (64*i)
            for bit in bits(val, one_indexed=False):
                ret.append(bit)
        return cls(ret)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('cpu_set_t')

import rsyscall.far
class SchedTask(rsyscall.far.Task):
    async def sched_setaffinity(self, mask: WrittenPointer[CpuSet]) -> None:
        with mask.borrow(self) as mask_n:
            await _sched_setaffinity(self.sysif, 0, mask.size(), mask_n)

    async def sched_getaffinity(self, mask: Pointer[CpuSet]) -> Pointer[CpuSet]:
        with mask.borrow(self) as mask_n:
            await _sched_getaffinity(self.sysif, 0, mask.size(), mask_n)
        return mask

    async def setns(self, fd: FileDescriptor, nstype: CLONE) -> None:
        fd._validate()
        await _setns(self.sysif, fd.near, nstype)

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS
import rsyscall.near as near

async def _clone(sysif: SyscallInterface, flags: int, child_stack: t.Optional[near.Address],
                ptid: t.Optional[near.Address], ctid: t.Optional[near.Address],
                newtls: t.Optional[near.Address]) -> near.Process:
    # We don't use CLONE_THREAD, so we can say without confusion, that clone returns a Process.
    if child_stack is None:
        child_stack = 0 # type: ignore
    if ptid is None:
        ptid = 0 # type: ignore
    if ctid is None:
        ctid = 0 # type: ignore
    if newtls is None:
        newtls = 0 # type: ignore
    return near.Process(await sysif.syscall(SYS.clone, flags, child_stack, ptid, ctid, newtls))

async def _unshare(sysif: SyscallInterface, flags: CLONE) -> None:
    await sysif.syscall(SYS.unshare, flags)

async def _sched_setaffinity(sysif: SyscallInterface, pid: int, cpusetsize: int, mask: near.Address) -> None:
    await sysif.syscall(SYS.sched_setaffinity, pid, cpusetsize, mask)

async def _sched_getaffinity(sysif: SyscallInterface, pid: int, cpusetsize: int, mask: near.Address) -> None:
    await sysif.syscall(SYS.sched_getaffinity, pid, cpusetsize, mask)

async def _setns(sysif: SyscallInterface, fd: near.FileDescriptor, nstype: CLONE) -> None:
    await sysif.syscall(SYS.setns, fd, nstype)


#### Tests ####
from unittest import TestCase
class TestEpoll(TestCase):
    def test_cpu_set(self) -> None:
        initial = CpuSet([42])
        output = CpuSet.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
