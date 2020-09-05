"Interfaces and basic functionality for our serialization framework."
from __future__ import annotations
import abc
import os
import typing as t
import struct
from dataclasses import dataclass

T = t.TypeVar('T')
class Serializer(t.Generic[T]):
    """An object encapsulating the information required to serialize or deserialize some value of some type.

    This may only work for one specific value of that type; for example, to
    deserialize a type containing pointers (encoded as addresses), we must have
    a serializer that knows about those addresses and can return the
    corresponding Python object Pointers.

    """
    def to_bytes(self, val: T) -> bytes:
        "Serialize this value `val` to bytes"
        raise NotImplementedError("to_bytes not implemented on", type(self))

    def from_bytes(self, data: bytes) -> T:
        "Deserialize a value from `data`"
        raise NotImplementedError("from_bytes not implemented on", type(self))

T_has_serializer = t.TypeVar('T_has_serializer', bound='HasSerializer')
class HasSerializer:
    "Something which can return a serializer for itself"
    @abc.abstractmethod
    def get_self_serializer(self: T_has_serializer, task) -> Serializer[T_has_serializer]:
        """Return a serializer for this value

        Note that, as discussed in the Serializer docstring, the serializer
        returned may only work for the specific value that this method was
        called on, not any other values of the same type.

        """
        pass

T_fixed_serializer = t.TypeVar('T_fixed_serializer', bound='FixedSerializer')
class FixedSerializer(HasSerializer):
    "Something which, if we know its class, can be serialized and deserialized"
    @classmethod
    @abc.abstractmethod
    def get_serializer(cls: t.Type[T_fixed_serializer], task) -> Serializer[T_fixed_serializer]:
        "Return a Serializer for this class"
        pass

    def get_self_serializer(self: T_fixed_serializer, task) -> Serializer[T_fixed_serializer]:
        """Return a Serializer for this value

        Since this class is a FixedSerializer, we can return a serializer that is
        independent of any specific value by calling get_serializer. Which we do.

        """
        return type(self).get_serializer(task)

T_fixed_size = t.TypeVar('T_fixed_size', bound='FixedSize')
class FixedSize(FixedSerializer):
    """Something which, if we know its class, can be serialized and deserialized to a fixed length bytestring

    These are fixed-size structures; for example, most C structs.
    """
    @classmethod
    @abc.abstractmethod
    def sizeof(cls) -> int:
        "Return the length of the bytestring that the serializer for this class will return"
        pass

class Serializable(FixedSerializer):
    "A helper class for FixedSerializer; the serialization methods are defined directly on the class"
    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        """Directly serialize the value `self` as bytes

        We use this as the Serializer.to_bytes method through the magic of duck typing;
        using this function from the underlying class gives us a function which takes a
        value (which it calls `self`) and does serialization for that value.
        """
        pass

    T_serializable = t.TypeVar('T_serializable', bound='Serializable')
    @classmethod
    def from_bytes(cls: t.Type[T_serializable], data: bytes) -> T_serializable:
        "Return a value of type `cls` deserialized from `data`"
        raise NotImplementedError("from_bytes not implemented on", cls)
    @classmethod
    def get_serializer(cls: t.Type[T_serializable], task) -> Serializer[T_serializable]: # type: ignore
        """Return a "serializer" for this class - it's actually just this class itself.

        Yay, duck typing!
        """
        return cls # type: ignore

class Struct(Serializable, FixedSize):
    "A helper class for FixedSize; the serialization methods are defined directly on the class"
    pass

def bits(n: int, one_indexed: bool=True) -> t.Iterator[int]:
    "Yield the bit indices that are set in this integer"
    while n:
        b = n & (~n+1)
        yield (b.bit_length() - (0 if one_indexed else 1))
        n ^= b

# mypy is very upset with me for inheriting from int and overriding int's methods in an incompatible way
class Int32(Struct, int): # type: ignore
    "A 32-bit integer, as used by many syscalls"
    def to_bytes(self) -> bytes: # type: ignore
        return struct.pack('i', self)

    T = t.TypeVar('T', bound='Int32')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T: # type: ignore
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        val, = struct.unpack_from('i', data)
        return cls(val)
        
    @classmethod
    def sizeof(cls) -> int:
        return struct.calcsize('i')

class Int64(Struct, int): # type: ignore
    "A 64-bit integer, as used by many syscalls"
    def to_bytes(self) -> bytes: # type: ignore
        return struct.pack('l', self)

    T = t.TypeVar('T', bound='Int64')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T: # type: ignore
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        val, = struct.unpack_from('l', data)
        return cls(val)

    @classmethod
    def sizeof(cls) -> int:
        return struct.calcsize('l')

@dataclass
class StructList(t.Generic[T_fixed_size], HasSerializer):
    "A list of serializable, fixed-size structures"
    cls: t.Type[T_fixed_size]
    elems: t.List[T_fixed_size]

    def get_self_serializer(self, task) -> StructListSerializer[T_fixed_size]:
        return StructListSerializer(self.cls, self.cls.get_serializer(task))

@dataclass
class StructListSerializer(t.Generic[T_fixed_size], Serializer[StructList[T_fixed_size]]):
    "The serializer for a StructList"
    cls: t.Type[T_fixed_size]
    ser: Serializer[T_fixed_size]

    def to_bytes(self, val: StructList[T_fixed_size]) -> bytes:
        return b"".join(self.ser.to_bytes(ent) for ent in val.elems)

    def from_bytes(self, data: bytes) -> StructList[T_fixed_size]:
        entries = []
        while len(data) > 0:
            ent = self.ser.from_bytes(data)
            entries.append(ent)
            data = data[self.cls.sizeof():]
        return StructList(self.cls, entries)

def strpath_to_null_terminated_bytes(val: t.Union[str, os.PathLike]) -> bytes:
    return os.fsencode(val) + b'\0'

def string_from_null_terminated_bytes(data: bytes) -> str:
    try:
        nullidx = data.index(b'\0')
    except ValueError:
        return os.fsdecode(data)
    else:
        return os.fsdecode(data[0:nullidx])

T_pathlike = t.TypeVar('T_pathlike', bound=os.PathLike)
@dataclass
class PathLikeSerializer(Serializer[T_pathlike]):
    cls: t.Type[T_pathlike]

    @staticmethod
    def to_bytes(val: T_pathlike) -> bytes:
        return strpath_to_null_terminated_bytes(val)

    def from_bytes(self, data: bytes) -> T_pathlike:
        # We assume that any PathLike can be constructed by just passing a single string to its constructor.
        # That's not actually true - os.DirEntry, for example, can't be constructed directly in this way.
        # But, this is Python, so if it quacks, it ships.
        return self.cls(string_from_null_terminated_bytes(data)) # type: ignore

class StrSerializer(Serializer[str]):
    @staticmethod
    def to_bytes(val: str) -> bytes:
        return strpath_to_null_terminated_bytes(val)

    @staticmethod
    def from_bytes(data: bytes) -> str:
        return string_from_null_terminated_bytes(data)
