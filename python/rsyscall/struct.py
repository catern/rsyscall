import abc
import typing as t

T_struct = t.TypeVar('T_struct', bound='Struct')
class Struct:
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

