"`#include <linux/futex.h>`"
from __future__ import annotations
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
import enum
from dataclasses import dataclass
from rsyscall.struct import Struct
from rsyscall.handle import Pointer, WrittenPointer

FUTEX_WAITERS: int = lib.FUTEX_WAITERS
FUTEX_TID_MASK: int = lib.FUTEX_TID_MASK

@dataclass
class FutexNode(Struct):
    # this is our bundle of struct robust_list with a futex.  since it's tricky to handle the
    # reference management of taking a reference to just one field in a structure (the futex, in
    # cases where we don't care about the robust list), we always deal in the entire FutexNode
    # structure whenever we talk about futexes. that's a bit of overhead but we barely use futexes,
    # so it's fine.
    next: t.Optional[Pointer[FutexNode]]
    futex: int

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct futex_node*', {
            # technically we're supposed to have a pointer to the first node in the robust list to
            # indicate the end.  but that's tricky to do. so instead let's just use a NULL pointer;
            # the kernel will EFAULT when it hits the end. make sure not to map 0, or we'll
            # break. https://imgflip.com/i/2zwysg
            'list': (ffi.cast('struct robust_list*', int(self.next.near)) if self.next else ffi.NULL,),
            'futex': self.futex,
        })
        return bytes(ffi.buffer(struct))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct futex_node')

@dataclass
class RobustListHead(Struct):
    first: WrittenPointer[FutexNode]

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct robust_list_head*', {
            'list': (ffi.cast('struct robust_list*', int(self.first.near)),),
            'futex_offset': ffi.offsetof('struct futex_node', 'futex'),
            'list_op_pending': ffi.NULL,
        })
        return bytes(ffi.buffer(struct))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct robust_list_head')

#### Classes ####
import rsyscall.far
from rsyscall.handle.pointer import WrittenPointer

class FutexTask(rsyscall.far.Task):
    async def set_robust_list(self, head: WrittenPointer[RobustListHead]) -> None:
        with head.borrow(self):
            await _set_robust_list(self.sysif, head.near, head.size())

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _set_robust_list(sysif: SyscallInterface, head: near.Address, len: int) -> None:
    await sysif.syscall(SYS.set_robust_list, head, len)
