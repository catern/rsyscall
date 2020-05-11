"Types to represent paths, used by many syscalls"
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
    """A version of pathlib.PurePosixPath which is safe to inherit from

    pathlib does a lot of crazy stuff which makes it hard to inherit from.  This
    class insulates us from that stuff, so it can be inherited from naively.

    """
    def __new__(cls, *args, **kwargs) -> PurePosixPath:
        """Override pathlib.PurePath.__new__ to restore default behavior

        pathlib.PurePath inherits from object, so we just use object's __new__.
        """
        return object.__new__(cls)

    def __init__(self, *args) -> None:
        """Override pathlib.PurePath.__init__ to create more sane behavior

        We copy a small amount of code from pathlib.PurePath._from_parts to implement this
        method.
        """
        drv, root, parts = self._parse_args(args) # type: ignore
        self._drv = drv
        self._root = root
        self._parts = parts

class Path(PurePosixPath, Serializable):
    """A serializable path, with all the methods of pathlib.PurePath.

    It would be nice if we could just use pathlib.PurePosixPath rather than
    inherit from it; but it's not clear how to make that type-safe. Plus,
    requiring the user to import pathlib would encourage them to use
    pathlib.Path; we'd rather they stay within rsyscall.

    """
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
    "An empty path; useful for *at syscalls which take this as a sentinel value" 
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
