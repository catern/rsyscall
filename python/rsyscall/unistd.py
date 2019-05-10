from __future__ import annotations
import enum
import os
from rsyscall.struct import Serializer, FixedSerializer, Serializable
import struct
import typing as t
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer, Task
else:
    Pointer = t.Optional

class SEEK(enum.IntEnum):
    SET = os.SEEK_SET

class Arg(bytes, Serializable):
    def to_bytes(self) -> bytes:
        return self + b'\0'

    T = t.TypeVar('T', bound='Arg')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        try:
            nullidx = data.index(b'\0')
        except ValueError:
            return cls(data)
        else:
            return cls(data[0:nullidx])

T_arglist = t.TypeVar('T_arglist', bound='ArgList')
class ArgList(t.List[Pointer[Arg]], FixedSerializer):
    @classmethod
    def get_serializer(cls, task: Task) -> Serializer[T_arglist]:
        return ArgListSerializer()

import struct
class ArgListSerializer(Serializer[T_arglist]):
    def to_bytes(self, arglist: T_arglist) -> bytes:
        ret = b""
        for ptr in arglist:
            ret += struct.Struct("Q").pack(int(ptr.near))
        ret += struct.Struct("Q").pack(0)
        return ret

    def from_bytes(self, data: bytes) -> T_arglist:
        raise Exception("can't get pointer handles from raw bytes")
