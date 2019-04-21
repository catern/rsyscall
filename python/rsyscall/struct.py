import abc
import typing as t
import struct
from dataclasses import dataclass

T_serializable = t.TypeVar('T_serializable', bound='Serializable')
class Serializable:
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls: t.Type[T_serializable], data: bytes) -> T_serializable: ...

T_struct = t.TypeVar('T_struct', bound='Struct')
class Struct(Serializable):
    "A fixed-size structure."
    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        "This method is allowed to return less than sizeof() bytes, as an optimization."
        ...
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls: t.Type[T_struct], data: bytes) -> T_struct: ...
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

@dataclass
class Int32(Struct):
    val: int

    def to_bytes(self) -> bytes:
        return struct.pack('i', self.val)

    T = t.TypeVar('T', bound='Int32')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        val, = struct.pack('i', data)
        return cls(val)
        
    @classmethod
    def sizeof(cls) -> int:
        return struct.calcsize('i')
