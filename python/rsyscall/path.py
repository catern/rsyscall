from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Serializable
import typing as t
import os
from pathlib import PurePosixPath

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
