"#include <sched.h>"
from __future__ import annotations
from rsyscall._raw import lib # type: ignore
from rsyscall.struct import Serializable, Serializer
from dataclasses import dataclass
import enum
import typing as t
import struct
import contextlib
if t.TYPE_CHECKING:
    from rsyscall.handle import Task, Pointer
    from rsyscall.loader import NativeFunction

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
        return struct.Struct("Q").pack(int(self.function.near)) + self.serializer.to_bytes(self.data)

    T_stack = t.TypeVar('T_stack', bound='Stack')
    @classmethod
    def from_bytes(cls: t.Type[T_stack], data: bytes) -> T_stack:
        raise Exception("nay")

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS
import rsyscall.near as near

async def _clone(sysif: SyscallInterface, flags: int, child_stack: near.Address,
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

