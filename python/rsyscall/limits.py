"`#include <limits.h>`"
from rsyscall._raw import ffi, lib # type: ignore

NAME_MAX: int = lib.NAME_MAX
