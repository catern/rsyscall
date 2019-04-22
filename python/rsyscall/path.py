from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Serializable, Struct
import typing as t
import os
import pathlib

if t.TYPE_CHECKING:
    PathLike = os.PathLike
else:
    PathLike = object

class PurePosixPath(pathlib.PurePosixPath):
    # pathlib does a lot of crazy stuff which makes it hard to inherit
    # from. this class insulates us from that stuff, so it can just be
    # inherited from naively.
    def __new__(cls, *args, **kwargs) -> None:
        # pathlib.PurePath inherits from object
        return object.__new__(cls)

    def __init__(self, *args) -> None:
        # copied from pathlib.PurePath._from_parts
        drv, root, parts = self._parse_args(args) # type: ignore
        self._drv = drv
        self._root = root
        self._parts = parts

class Path(PurePosixPath, Serializable):
    def to_bytes(self) -> bytes:
        return bytes(self) + b'\0'

    T = t.TypeVar('T', bound='Path')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        try:
            nullidx = data.index(b'\0')
        except ValueError:
            return cls(os.fsdecode(data))
        else:
            return cls(os.fsdecode(data[0:nullidx]))

class EmptyPath(Struct):
    def to_bytes(self) -> bytes:
        return b'\0'

    T = t.TypeVar('T', bound='EmptyPath')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        return cls()

    @classmethod
    def sizeof(cls) -> int:
        return 1


#### Tests ####
from unittest import TestCase

class TestPath(TestCase):
    def test_path(self) -> None:
        path = Path('/a/b')
        self.assertEqual(Path.from_bytes(path.to_bytes()), path)
        data = b'a/b\0'
        self.assertEqual(Path.from_bytes(data).to_bytes(), data)
        data = b'./a/b//\0\0\0'
        # ./, trailing /, and trailing \0 are all strippd
        self.assertNotEqual(Path.from_bytes(data).to_bytes(), data)
