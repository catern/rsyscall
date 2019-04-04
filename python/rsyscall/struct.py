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

def bits(n: int, one_indexed: bool=True) -> t.Iterator[int]:
    "Yields the bit indices that are set in this integer"
    while n:
        b = n & (~n+1)
        yield (b.bit_length() - (0 if one_indexed else 1))
        n ^= b
