from __future__ import annotations
import abc
import typing as t
import struct
from dataclasses import dataclass

T_serializable = t.TypeVar('T_serializable', bound='Serializable')

T = t.TypeVar('T')
class Serializer(t.Generic[T]):
    @abc.abstractmethod
    def to_bytes(self, val: T) -> bytes: ...
    @abc.abstractmethod
    def from_bytes(self, data: bytes) -> T: ...

class Serializable:
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls: t.Type[T_serializable], data: bytes) -> T_serializable: ...
    @classmethod
    def get_serializer(cls: t.Type[T_serializable]) -> Serializer[T_serializable]:
        return cls # type: ignore

T_struct = t.TypeVar('T_struct', bound='Struct')
class Struct(Serializable):
    "A fixed-size structure."
    @classmethod
    @abc.abstractmethod
    def sizeof(cls) -> int:
        "The maximum size of this structure."
        ...

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
