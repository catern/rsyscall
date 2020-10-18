"A slightly improved version of `pathlib.PurePosixPath`"
from __future__ import annotations
import pathlib

class Path(pathlib.PurePosixPath):
    """A version of `pathlib.PurePosixPath` which is safe to inherit from

    `pathlib` does a lot of crazy stuff which makes it hard to inherit from.  This
    class insulates us from that stuff, so it can be inherited from naively.

    We use this as Path, rather than using `pathlib.Path`, to avoid confusion about
    `pathlib.Path`'s filesystem-interaction methods, which are not rsyscall-aware.

    """
    def __new__(cls, *args, **kwargs) -> Path:
        """Override `pathlib.PurePath.__new__` to restore default behavior

        `pathlib.PurePath` inherits from `object`, so we just use `object.__new__`.
        """
        return object.__new__(cls)

    def __init__(self, *args) -> None:
        """Override `pathlib.PurePath.__init__` to create more sane behavior

        We copy a small amount of code from `pathlib.PurePath._from_parts` to implement this
        method.
        """
        drv, root, parts = self._parse_args(args) # type: ignore
        self._drv = drv
        self._root = root
        self._parts = parts
