from rsyscall._raw import ffi, lib # type: ignore
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

class SOCK(enum.IntEnum):
    DGRAM = socket.SOCK_DGRAM
    STREAM = socket.SOCK_STREAM
    RAW = socket.SOCK_RAW

class SOL(enum.IntEnum):
    """Stands for Sock Opt Level

    This is what should be passed as the "level" argument to
    getsockopt/setsockopt.

    """
    SOCKET = lib.SOL_SOCKET
    IP = lib.SOL_IP

T_addr = t.TypeVar('T_addr', bound='Address')
# this is just a marker type to indicate different kinds of sockaddrs
class Address(Struct):
    addrlen: int
    @classmethod
    @abc.abstractmethod
    def from_bytes(cls: t.Type[T_addr], data: bytes) -> T_addr: ...
    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...
    @classmethod
    @abc.abstractmethod
    def sizeof(cls) -> int: ...

    @classmethod
    def parse(cls: t.Type[T_addr], data: bytes) -> T_addr:
        return cls.from_bytes(data)
