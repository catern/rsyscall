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
        # uhhh I need to, I guess, strip the null byte?
        # hmmmmmmmmmmmmmM
        # HUMMMMM
        return cls(os.fsdecode(data))


#### Tests ####
from unittest import TestCase

class TestPath(TestCase):
    def test_path(self) -> None:
        x = Path.to_bytes(Path.from_bytes(b"/a/b/"))
        print(x)
