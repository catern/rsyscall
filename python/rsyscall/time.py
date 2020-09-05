"`#include <time.h>`"
from __future__ import annotations
from rsyscall._raw import lib, ffi # type: ignore
from rsyscall.struct import Struct
import typing as t
from decimal import Decimal
import decimal
import math
from dataclasses import dataclass

NSEC_PER_SEC = 1_000_000_000

@dataclass
class Timespec:
    """struct timespec, as used by several time-related system-calls.

    This struct specifies time with nanosecond precision, but there's no good standard way
    in Python to represent such times. The growing standard is to use an integer number of
    nanoseconds, but that's easy to confuse with an integer number of seconds, and most
    functions don't take number-of-nanoseconds, they take number-of-seconds.

    So, this class supports conversion to and from a bunch of other formats.

    See the proposal of using Decimal to represent nanosecond timestamps:

    https://www.python.org/dev/peps/pep-0410/
    https://www.python.org/dev/peps/pep-0564/
    https://vstinner.github.io/python37-pep-564-nanoseconds.html

    The rejection of that proposal by Guido:

    https://mail.python.org/pipermail/python-dev/2012-February/116837.html
    https://bugs.python.org/issue23084

    """
    sec: int
    nsec: int

    def to_decimal(self) -> Decimal:
        raise NotImplementedError

    def to_nanos(self) -> int:
        raise NotImplementedError

    def _to_cffi_dict(self) -> t.Dict[str, int]:
        return {
            "tv_sec": self.sec,
            "tv_nsec": self.nsec,
        }

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct timespec const*', self._to_cffi_dict())))

    T = t.TypeVar('T', bound='Timespec')
    @classmethod
    def from_float(cls: t.Type[T], value: t.Union[float, Decimal, Timespec]) -> T:
        if isinstance(value, Timespec):
            return cls(value.sec, value.nsec)
        elif isinstance(value, Decimal):
            frac, i = decimal.getcontext().divmod(value, Decimal(1))
            return cls(int(i), int(frac*NSEC_PER_SEC))
        else:
            fractional, integer = math.modf(value)
            return cls(int(integer), int(fractional*NSEC_PER_SEC))

    @classmethod
    def from_nanos(cls: t.Type[T], nsec: int) -> T:
        raise NotImplementedError

    @classmethod
    def from_cffi(cls: t.Type[T], cffi_value: t.Any) -> T:
        return cls(cffi_value.tv_sec, cffi_value.tv_nsec)

    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct timespec*', ffi.from_buffer(data))
        return cls.from_cffi(struct)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct timespec')

@dataclass
class Itimerspec(Struct):
    interval: Timespec
    value: Timespec

    def __init__(self, interval: t.Union[float, Decimal, Timespec],
                 value: t.Union[float, Decimal, Timespec]) -> None:
        self.interval = Timespec.from_float(interval)
        self.value = Timespec.from_float(interval)

    def _to_cffi_dict(self) -> t.Dict[str, t.Dict[str, int]]:
        return {
            "it_interval": self.interval._to_cffi_dict(),
            "it_value": self.value._to_cffi_dict(),
        }

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct itimerspec const*', self._to_cffi_dict())))

    T = t.TypeVar('T', bound='Itimerspec')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct itimerspec*', ffi.from_buffer(data))
        return cls(Timespec.from_cffi(struct.it_interval), Timespec.from_cffi(struct.it_value))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct itimerspec')

#### Tests ####
from unittest import TestCase
class TestTime(TestCase):
    def test_timespec(self) -> None:
        initial = Timespec.from_float(Decimal('4.1'))
        output = Timespec.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)

    def test_itimerspec(self) -> None:
        initial = Itimerspec(Timespec.from_float(Decimal('1.2')), Timespec.from_float(Decimal('3.4')))
        output = Itimerspec.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
