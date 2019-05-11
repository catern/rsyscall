from __future__ import annotations
import abc
import typing as t
import struct
from dataclasses import dataclass

T = t.TypeVar('T')
class Serializer(t.Generic[T]):
    def to_bytes(self, val: T) -> bytes:
        raise NotImplementedError("to_bytes not implemented on", type(self))

    def from_bytes(self, data: bytes) -> T:
        raise NotImplementedError("from_bytes not implemented on", type(self))

T_has_serializer = t.TypeVar('T_has_serializer', bound='HasSerializer')
class HasSerializer:
    @abc.abstractmethod
    def get_self_serializer(self: T_has_serializer, task) -> Serializer[T_has_serializer]: ...

T_fixed_serializer = t.TypeVar('T_fixed_serializer', bound='FixedSerializer')
class FixedSerializer(HasSerializer):
    @classmethod
    @abc.abstractmethod
    def get_serializer(cls: t.Type[T_fixed_serializer], task) -> Serializer[T_fixed_serializer]: ... # type: ignore

    def get_self_serializer(self: T_fixed_serializer, task) -> Serializer[T_fixed_serializer]:
        return type(self).get_serializer(task)

T_fixed_size = t.TypeVar('T_fixed_size', bound='FixedSize')
class FixedSize(FixedSerializer):
    @classmethod
    @abc.abstractmethod
    def sizeof(cls) -> int: ...

T_serializable = t.TypeVar('T_serializable', bound='Serializable')
class Serializable(FixedSerializer):
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...
    @classmethod
    def from_bytes(cls: t.Type[T_serializable], data: bytes) -> T_serializable:
        raise NotImplementedError("from_bytes not implemented on", cls)
    @classmethod
    def get_serializer(cls: t.Type[T_serializable], task) -> Serializer[T_serializable]: # type: ignore
        return cls # type: ignore

T_struct = t.TypeVar('T_struct', bound='Struct')
class Struct(Serializable, FixedSize):
    pass

def bits(n: int, one_indexed: bool=True) -> t.Iterator[int]:
    "Yields the bit indices that are set in this integer"
    while n:
        b = n & (~n+1)
        yield (b.bit_length() - (0 if one_indexed else 1))
        n ^= b

# mypy is very upset with me for inheriting from int and overriding int's methods in an incompatible way
class Int32(Struct, int): # type: ignore
    def to_bytes(self) -> bytes: # type: ignore
        return struct.pack('i', self)

    T = t.TypeVar('T', bound='Int32')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T: # type: ignore
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        val, = struct.pack('i', data)
        return cls(val)
        
    @classmethod
    def sizeof(cls) -> int:
        return struct.calcsize('i')

class Bytes(bytes, Serializable):
    def to_bytes(self) -> bytes:
        return self

    T = t.TypeVar('T', bound='Bytes')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        return cls(data)

@dataclass
class StructList(t.Generic[T_struct], HasSerializer):
    cls: t.Type[T_struct]
    elems: t.List[T_struct]

    def get_self_serializer(self, task) -> StructListSerializer[T_struct]:
        return StructListSerializer(self.cls)

@dataclass
class StructListSerializer(t.Generic[T_struct], Serializer[StructList[T_struct]]):
    cls: t.Type[T_struct]

    def to_bytes(self, val: StructList[T_struct]) -> bytes:
        return b"".join(ent.to_bytes() for ent in val.elems)

    @classmethod
    def from_bytes(self, data: bytes) -> StructList[T_struct]:
        entries = []
        while len(data) > 0:
            ent = self.cls.from_bytes(data)
            entries.append(ent)
            data = data[self.cls.sizeof():]
        return StructList(self.cls, entries)
