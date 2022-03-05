"The high-level interfaces to memory"
from __future__ import annotations
from dneio import run_all
from rsyscall.handle import Task, Pointer, WrittenPointer
from rsyscall.memory.allocation_interface import AllocationInterface
from rsyscall.memory.allocator import AllocatorInterface
from rsyscall.struct import FixedSize, T_fixed_size, HasSerializer, T_has_serializer, FixedSerializer, T_fixed_serializer, Serializer, PathLikeSerializer, T_pathlike, StrSerializer
from rsyscall.sys.mman import MemoryMapping
import functools
import os
import rsyscall.near.types as near
import rsyscall.far as far

import typing as t

__all__ = [
    "RAM",
]

class BytesSerializer(Serializer[bytes]):
    def to_bytes(self, val: bytes) -> bytes:
        return val

    def from_bytes(self, data: bytes) -> bytes:
        return data

T = t.TypeVar('T')
class RAM:
    """Central user-friendly class for accessing memory.

    Future work: An option to allocate "const" pointers, which we
    could cache and reuse each time they're requested. This would be
    useful for small pieces of memory which are very frequently used.

    """
    def __init__(self, 
                 task: Task,
                 allocator: AllocatorInterface,
    ) -> None:
        self.task = task
        self.allocator = allocator

    @t.overload
    async def malloc(self, cls: t.Type[T_fixed_size]) -> Pointer[T_fixed_size]: ...
    @t.overload
    async def malloc(self, cls: t.Type[T_fixed_serializer], size: int) -> Pointer[T_fixed_serializer]: ...
    @t.overload
    async def malloc(self, cls: t.Type[T_pathlike], size: int) -> Pointer[T_pathlike]: ...
    @t.overload
    async def malloc(self, cls: t.Type[str], size: int) -> Pointer[str]: ...
    @t.overload
    async def malloc(self, cls: t.Type[bytes], size: int) -> Pointer[bytes]: ...

    # have to type: ignore because of https://github.com/python/mypy/issues/9420
    async def malloc(self, cls: t.Union[  # type: ignore
            t.Type[T_fixed_size],
            t.Type[T_fixed_serializer],
            t.Type[T_pathlike],
            t.Type[str],
            t.Type[bytes],
    ], size: t.Optional[int]=None,
    ) -> t.Union[
        Pointer[T_fixed_size],
        Pointer[T_fixed_serializer],
        Pointer[T_pathlike],
        Pointer[str],
        Pointer[bytes],
    ]:
        "Allocate a typed space in memory, sized according to the size of the type or an explicit size argument"
        if size is None:
            if not issubclass(cls, FixedSize):
                raise Exception("non-FixedSize cls passed to malloc without specifying size to allocate", cls)
            ptr: Pointer = await self.malloc_serializer(cls.get_serializer(self.task), cls.sizeof(), cls)
            return ptr
        else:
            if issubclass(cls, FixedSize):
                raise Exception("Can't pass a FixedSize cls to malloc and also specify the size argument", cls, size)
            if issubclass(cls, FixedSerializer):
                ptr = await self.malloc_serializer(cls.get_serializer(self.task), size, cls)
                return ptr
            # special-case Path/str/bytes so that they don't have to get wrapped just for rsyscall
            elif issubclass(cls, os.PathLike):
                pathlike_cls = t.cast(t.Type[T_pathlike], cls)
                return await self.malloc_serializer(PathLikeSerializer(pathlike_cls), size, pathlike_cls)
            elif issubclass(cls, str):
                return await self.malloc_serializer(StrSerializer(), size, str)
            elif issubclass(cls, bytes):
                return await self.malloc_serializer(BytesSerializer(), size, bytes)
            else:
                raise Exception("don't know how to find serializer for", cls)


    @t.overload
    async def ptr(self, data: T_has_serializer) -> WrittenPointer[T_has_serializer]: ...
    @t.overload
    async def ptr(self, data: T_pathlike) -> WrittenPointer[T_pathlike]: ...
    @t.overload
    async def ptr(self, data: str) -> WrittenPointer[str]: ...
    @t.overload
    async def ptr(self, data: t.Union[bytes]) -> WrittenPointer[bytes]: ...
    async def ptr(self, data: t.Union[T_has_serializer, T_pathlike, str, bytes],
    ) -> t.Union[
        WrittenPointer[T_has_serializer],
        WrittenPointer[T_pathlike],
        WrittenPointer[str], WrittenPointer[bytes],
    ]:
        "Take some serializable data and return a pointer in memory containing it."
        if isinstance(data, HasSerializer):
            serializer = data.get_self_serializer(self.task)
            data_bytes = serializer.to_bytes(data)
            ptr: Pointer = await self.malloc_serializer(
                serializer, len(data_bytes), type(data))
            return await self._write_to_pointer(ptr, data, data_bytes)
        elif isinstance(data, os.PathLike):
            path_serializer = PathLikeSerializer(type(data))
            data_bytes = path_serializer.to_bytes(data)
            ptr = await self.malloc_serializer(path_serializer, len(data_bytes), type(data))
            return await self._write_to_pointer(ptr, data, data_bytes)
        elif isinstance(data, str):
            str_serializer = StrSerializer()
            data_bytes = str_serializer.to_bytes(data)
            ptr = await self.malloc_serializer(str_serializer, len(data_bytes), type(data))
            return await self._write_to_pointer(ptr, data, data_bytes)
        elif isinstance(data, bytes):
            ptr = await self.malloc(bytes, len(data))
            return await self._write_to_pointer(ptr, data, data)
        else:
            raise Exception("don't know how to serialize data passed to ptr", data)

    async def malloc_serializer(
            self, serializer: Serializer[T], size: int, typ: t.Type[T],
    ) -> Pointer[T]:
        """Allocate a typed space in memory using an explicitly-specified Serializer.

        This is useful only in relatively niche situations.

        """
        mapping, allocation = await self.allocator.malloc(size, alignment=1)
        try:
            return Pointer(mapping, serializer, allocation, typ)
        except:
            allocation.free()
            raise

    async def _write_to_pointer(self, ptr: Pointer[T], data: T, data_bytes: bytes) -> WrittenPointer[T]:
        try:
            return await ptr.write(data)
        except:
            ptr.free()
            raise
