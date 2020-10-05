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
    Borrowable, Pointer, WrittenPointer, FileDescriptor, Task,
    Stack,
)
from rsyscall.sys.mman import MemoryMapping
from rsyscall.memory.allocation_interface import AllocationInterface
from rsyscall.memory.transport import MemoryGateway
import rsyscall.near.types as near
import rsyscall.far as far
from rsyscall.struct import Serializer

__all__ = [
    "NativeFunction",
    "Trampoline",
    "NativeLoader",
]

class NativeFunction:
    """A native-code function

    For now, this is just an opaque marker type, but maybe later we'll
    actually be able to manipulate this as an object.

    """
    pass

@dataclass
class Trampoline(Borrowable):
    "A pointer to a native function plus some arguments passed by register"
    function: Pointer[NativeFunction]
    args: t.List[t.Union[FileDescriptor, WrittenPointer[Borrowable], Pointer, int]]

    def __post_init__(self) -> None:
        if len(self.args) > 6:
            raise Exception("only six arguments can be passed via trampoline")

    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None:
        "Borrow the function pointer and the arguments"
        stack.enter_context(self.function.borrow(task))
        for arg in self.args:
            if isinstance(arg, int):
                pass
            elif isinstance(arg, WrittenPointer):
                arg.value.borrow_with(stack, task)
            else:
                stack.enter_context(arg.borrow(task))

class TrampolineSerializer(Serializer[Trampoline]):
    def to_bytes(self, val: Trampoline) -> bytes:
        # at most six arguments
        args: t.List[int] = [0]*6
        for i, arg in enumerate(val.args):
            if isinstance(arg, FileDescriptor):
                args[i] = int(arg)
            elif isinstance(arg, Pointer):
                args[i] = int(arg.near)
            else:
                args[i] = int(arg)
        struct = ffi.new('struct rsyscall_trampoline_stack*', {
            'function': ffi.cast('void*', int(val.function.near)),
            'rdi': args[0],
            'rsi': args[1],
            'rdx': args[2],
            'rcx': args[3],
            'r8':  args[4],
            'r9':  args[5],
        })
        return bytes(ffi.buffer(struct))

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
    async def read(self, src: Pointer) -> bytes:
        raise Exception("shouldn't try to read")
    async def write(self, dest: Pointer, data: bytes) -> None:
        raise Exception("shouldn't try to write")

class NativeFunctionSerializer(Serializer[NativeFunction]):
    "Serializes NativeFunctions by throw exceptions if you call to_bytes/from_bytes :)"
    pass

@dataclass
class NativeLoader:
    """Loads native code object into memory where they can be called

    At the moment we don't actually load though - we just hardcode a
    set of available symbols that we use.

    """
    server_func: Pointer[NativeFunction]
    persistent_server_func: Pointer[NativeFunction]
    trampoline_func: Pointer[NativeFunction]
    futex_helper_func: Pointer[NativeFunction]

    @staticmethod
    def make_from_symbols(task: Task, symbols: t.Any) -> NativeLoader:
        """Create a NativeLoader by pulling functions from this "symbols" object by attribute

        This symbols object is either rsyscall._raw.lib, or a cffi struct;
        either way, the attributes are named as we expect in this function.

        """
        def to_handle(cffi_ptr) -> Pointer[NativeFunction]:
            pointer_int = int(ffi.cast('ssize_t', cffi_ptr))
            # TODO we're just making up a memory mapping that this pointer is inside;
            # we should figure out the actual mapping, and the size for that matter.
            mapping = MemoryMapping(task, near.MemoryMapping(pointer_int, 0, 1), far.File())
            return Pointer(mapping, NullGateway(), NativeFunctionSerializer(), StaticAllocation(), NativeFunction)
        return NativeLoader(
            server_func=to_handle(symbols.rsyscall_server),
            persistent_server_func=to_handle(symbols.rsyscall_persistent_server),
            trampoline_func=to_handle(symbols.rsyscall_trampoline),
            futex_helper_func=to_handle(symbols.rsyscall_futex_helper),
        )

    def make_trampoline_stack(self, trampoline: Trampoline) -> Stack[Trampoline]:
        "Make a stack that will invoke the passed trampoline as its immediate action"
        return Stack(self.trampoline_func, trampoline, TrampolineSerializer())
