"""`#include <net/if.h>`

The associated manpage is netdevice(7)

"""
from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.netinet.ip import SockaddrIn
from rsyscall.struct import Struct
import typing as t

__all__ = [
    "IFF_TUN",
    "TUNSETIFF",
    "SIOCGIFINDEX",
    "Ifreq",
]

IFF_TUN: int = lib.IFF_TUN
TUNSETIFF: int = lib.TUNSETIFF
SIOCGIFINDEX: int = lib.SIOCGIFINDEX

class CStringField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> str:
        data = bytes(ffi.buffer(getattr(instance.cffi, self.name)))
        try:
            valid_data = data[:data.index(b'\0')]
        except ValueError:
            valid_data = data
        return valid_data.decode()

    def __set__(self, instance, value: str) -> None:
        setattr(instance.cffi, self.name, value.encode() + b"\0")

class IntField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> int:
        return getattr(instance.cffi, self.name)

    def __set__(self, instance, value: int) -> None:
        setattr(instance.cffi, self.name, value)

class AddressField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> SockaddrIn:
        data_bytes = bytes(ffi.buffer(ffi.addressof(instance.cffi, self.name)))
        return SockaddrIn.from_bytes(data_bytes)

    def __set__(self, instance, value: SockaddrIn) -> None:
        data_bytes = value.to_bytes()
        ffi.memmove(ffi.addressof(instance.cffi, self.name),
                    ffi.from_buffer(data_bytes), len(data_bytes))

class Ifreq(Struct):
    """Representation of "struct ifreq"

    We have to be somewhat careful in how we represent this, since this struct
    is one big union, plus ifr_name which can be unset anyway.

    The way we handle this is, all the fields on this class are properties which
    extract some specific field from the union, stored as a cffi type.

    """
    name = CStringField("ifr_name")
    addr = AddressField("ifr_addr")
    ifindex = IntField("ifr_ifindex")
    flags = IntField("ifr_flags")
    
    def __init__(self, name: str=None, *, flags: int=None, cffi=None) -> None:
        if cffi is None:
            cffi = ffi.new('struct ifreq*')
        self.cffi = cffi
        if name is not None:
            self.name = name
        if flags is not None:
            self.flags = flags

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(self.cffi))

    T = t.TypeVar('T', bound='Ifreq')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) != cls.sizeof():
            raise Exception("data length", len(data),
                            "doesn't match actual length of struct ifreq", cls.sizeof())
        cffi = ffi.new('struct ifreq*')
        ffi.memmove(cffi, ffi.from_buffer(data), cls.sizeof())
        return cls(cffi=cffi)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct ifreq')

    def __str__(self) -> str:
        if self.name:
            return f"Ifreq({self.name}, ...)"
        else:
            # if it's an empty string, indicate that there's no name
            return "Ifreq(<no interface name>, ...)"


#### Tests ####
from unittest import TestCase
class TestIf(TestCase):
    def test_ifreq(self) -> None:
        initial = Ifreq()
        initial.name = "hello"
        initial.addr = SockaddrIn(42, "127.0.0.1")
        output = Ifreq.from_bytes(initial.to_bytes())
        self.assertEqual(initial.name, output.name)
        self.assertEqual(initial.addr.port, output.addr.port)
        self.assertEqual(initial.addr.addr, output.addr.addr)
