"""Access to native code functions

At some point we'll implement a loader here which can be used to load
objects into threads and return the functions inside them. For now, we
just have skeleton classes that hold pre-loaded functions.

"""
from __future__ import annotations
from rsyscall._raw import ffi # type: ignore
import contextlib
from dataclasses import dataclass
import typing as t
from rsyscall.handle import (
    Borrowable, Pointer, WrittenPointer, FileDescriptor, Task, AllocationInterface,
    Stack, MemoryGateway, MemoryMapping,
)
import rsyscall.near as near
from rsyscall.struct import Serializable, Serializer

__all__ = [
    "NativeFunction",
    "Trampoline",
    "NativeLoader",
]

class NativeFunction:
    pass

class NativeFunctionSerializer(Serializer[NativeFunction]):
    pass

@dataclass
class Trampoline(Serializable, Borrowable):
    "A Pointer to a native function plus some arguments passed by register"
    function: Pointer[NativeFunction]
    args: t.List[t.Union[FileDescriptor, WrittenPointer[Borrowable], Pointer, int]]

    def __post_init__(self) -> None:
        if len(self.args) > 6:
            raise Exception("only six arguments can be passed via trampoline")

    def to_bytes(self) -> bytes:
        args: t.List[int] = []
        for arg in self.args:
            if isinstance(arg, FileDescriptor):
                args.append(int(arg.near))
            elif isinstance(arg, Pointer):
                args.append(int(arg.near))
            else:
                args.append(int(arg))
        arg1, arg2, arg3, arg4, arg5, arg6 = args + [0]*(6 - len(args))
        struct = ffi.new('struct rsyscall_trampoline_stack*', {
            'function': ffi.cast('void*', int(self.function.near)),
            'rdi': int(arg1),
            'rsi': int(arg2),
            'rdx': int(arg3),
            'rcx': int(arg4),
            'r8':  int(arg5),
            'r9':  int(arg6),
        })
        return bytes(ffi.buffer(struct))

    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None:
        stack.enter_context(self.function.borrow(task))
        for arg in self.args:
            if isinstance(arg, int):
                pass
            elif isinstance(arg, WrittenPointer):
                arg.value.borrow_with(stack, task)
            else:
                stack.enter_context(arg.borrow(task))

    T = t.TypeVar('T', bound='Trampoline')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("not implemented")

class StaticAllocation(AllocationInterface):
    def offset(self) -> int:
        return 0

    def size(self) -> int:
        raise Exception

    def split(self, size: int) -> t.Tuple[AllocationInterface, AllocationInterface]:
        raise Exception

    def merge(self, other: AllocationInterface) -> AllocationInterface:
        raise Exception("can't merge")

    def free(self) -> None:
        pass

class NullGateway(MemoryGateway):
    async def batch_read(self, ops: t.List[Pointer]) -> t.List[bytes]:
        raise Exception("shouldn't try to read")
    async def batch_write(self, ops: t.List[t.Tuple[Pointer, bytes]]) -> None:
        raise Exception("shouldn't try to write")

@dataclass
class NativeLoader:
    server_func: Pointer[NativeFunction]
    persistent_server_func: Pointer[NativeFunction]
    trampoline_func: Pointer[NativeFunction]
    futex_helper_func: Pointer[NativeFunction]

    @staticmethod
    def make_from_symbols(task: Task, symbols: t.Any) -> NativeLoader:
        def to_handle(cffi_ptr) -> Pointer[NativeFunction]:
            pointer_int = int(ffi.cast('ssize_t', cffi_ptr))
            # TODO we're just making up a memory mapping that this pointer is inside;
            # we should figure out the actual mapping, and the size for that matter.
            mapping = MemoryMapping(task, near.MemoryMapping(pointer_int, 0, 1), near.File())
            return Pointer(mapping, NullGateway(), NativeFunctionSerializer(), StaticAllocation())
        return NativeLoader(
            server_func=to_handle(symbols.rsyscall_server),
            persistent_server_func=to_handle(symbols.rsyscall_persistent_server),
            trampoline_func=to_handle(symbols.rsyscall_trampoline),
            futex_helper_func=to_handle(symbols.rsyscall_futex_helper),
        )

    def make_trampoline_stack(self, trampoline: Trampoline) -> Stack[Trampoline]:
        return Stack(self.trampoline_func, trampoline, trampoline.get_serializer(None))
