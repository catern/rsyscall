from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import typing as t
import enum
import socket
from rsyscall.struct import Struct
import abc

class AF(enum.IntEnum):
    UNIX = socket.AF_UNIX
    NETLINK = socket.AF_NETLINK
    INET = socket.AF_INET
    INET6 = socket.AF_INET6

class Address(Struct):
    "This is just a marker type to indicate different kinds of sockaddrs"
    family: AF
    @classmethod
    def check_family(cls, family: AF) -> None:
        if cls.family != family:
            raise Exception("sa_family should be", cls.family, "is instead", family)

T_addr = t.TypeVar('T_addr', bound='Address')

family_to_class: t.Dict[AF, t.Type[Address]] = {}
def _register_sockaddr(sockaddr: t.Type[Address]) -> None:
    if sockaddr.family in family_to_class:
        raise Exception("tried to register sockaddr", sockaddr, "for family", sockaddr.family,
                        "but there's already a class registered for that family:",
                        family_to_class[sockaddr.family])
    family_to_class[sockaddr.family] = sockaddr

class SOCK(enum.IntFlag):
    # socket kinds
    DGRAM = socket.SOCK_DGRAM
    STREAM = socket.SOCK_STREAM
    RAW = socket.SOCK_RAW
    # flags that can be or'd in
    CLOEXEC = socket.SOCK_CLOEXEC
    NONBLOCK = socket.SOCK_NONBLOCK

class SOL(enum.IntEnum):
    """Stands for Sock Opt Level

    This is what should be passed as the "level" argument to
    getsockopt/setsockopt.

    """
    SOCKET = lib.SOL_SOCKET
    IP = lib.SOL_IP

class SO(enum.IntEnum):
    ERROR = lib.SO_ERROR

@dataclass
class GenericSockaddr(Address):
    family: AF
    data: bytes

    @classmethod
    def check_family(cls, family: AF) -> None:
        if cls.family != family:
            raise Exception("sa_family should be", cls.family, "is instead", family)

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('sa_family_t*', self.family))) + self.data

    T = t.TypeVar('T', bound='GenericSockaddr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T: # type: ignore
        family = ffi.cast('sa_family_t*', ffi.from_buffer(data))
        rest = data[ffi.sizeof('sa_family_t'):]
        return cls(
            family=AF(family[0]),
            data=rest
        )

    @classmethod
    def sizeof(cls) -> int:
        # this is the maximum size of a sockaddr
        return ffi.sizeof('struct sockaddr_storage')

    def parse(self) -> Address:
        cls = family_to_class[self.family]
        return cls.from_bytes(self.to_bytes())

# mypy is very upset with me for inheriting from int and overriding int's methods in an incompatible way
class Socklen(Struct, int): # type: ignore
    def to_bytes(self) -> bytes: # type: ignore
        return bytes(ffi.buffer(ffi.new('socklen_t*', self)))

    T = t.TypeVar('T', bound='Socklen')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T: # type: ignore
        struct = ffi.cast('socklen_t*', ffi.from_buffer(data))
        return cls(struct[0])

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('socklen_t')


#### Tests ####
from unittest import TestCase
class TestSocket(TestCase):
    def test_socklen(self) -> None:
        initial = Socklen(42)
        output = Socklen.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)
