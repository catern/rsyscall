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

class CLONE(enum.IntFlag):
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
    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None:
        raise NotImplementedError("borrow_with not implemented on", type(self))

T_borrowable = t.TypeVar('T_borrowable', bound=Borrowable)

@dataclass
class Stack(Serializable, t.Generic[T_borrowable]):
    function: Pointer
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

