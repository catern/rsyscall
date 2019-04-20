from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.netinet.ip import SockaddrIn
from rsyscall.struct import Struct
import typing as t

IFF_TUN: int = lib.IFF_TUN
TUNSETIFF: int = lib.TUNSETIFF
SIOCGIFINDEX: int = lib.SIOCGIFINDEX

class BytesField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> bytes:
        return bytes(ffi.buffer(getattr(instance.cffi, self.name)))

    def __set__(self, instance, value: bytes) -> None:
        setattr(instance.cffi, self.name, value)

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
        lib.memcpy(ffi.addressof(instance.cffi, self.name),
                   ffi.from_buffer(data_bytes), len(data_bytes))

class Ifreq(Struct):
    name = BytesField("ifr_name")
    addr = AddressField("ifr_addr")
    ifindex = IntField("ifr_ifindex")
    flags = IntField("ifr_flags")
    
    def __init__(self, name: bytes=None, *, flags: int=None, cffi=None) -> None:
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
        lib.memcpy(cffi, ffi.from_buffer(data), cls.sizeof())
        return cls(cffi=cffi)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct ifreq')

    def __str__(self) -> str:
        try:
            strname = self.name[:self.name.index(b'\0')].decode()
        except ValueError:
            strname = self.name.decode()
        if strname:
            return f"Ifreq({strname}, ...)"
        else:
            return "Ifreq(<no interface name>, ...)"
