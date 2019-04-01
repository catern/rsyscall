from __future__ import annotations
import abc
import typing as t

class Struct:
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls: t.Type[T_struct], data: bytes) -> T_struct: ...
    @classmethod
    @abc.abstractmethod
    def sizeof(cls) -> int: ...

T_struct = t.TypeVar('T_struct', bound=Struct)
