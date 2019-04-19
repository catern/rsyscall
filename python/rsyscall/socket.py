import socket
from rsyscall._raw import ffi, lib # type: ignore
import enum
from rsyscall.base import Address
import typing as t
from dataclasses import dataclass
import ipaddress

class AF(enum.IntEnum):
    UNIX = socket.AF_UNIX
    NETLINK = socket.AF_NETLINK
    INET6 = socket.AF_INET6

class SOCK(enum.IntEnum):
    DGRAM = socket.SOCK_DGRAM
    STREAM = socket.SOCK_STREAM
    RAW = socket.SOCK_RAW

class IPPROTO(enum.IntEnum):
    ICMPV6 = socket.IPPROTO_ICMPV6

class SOL(enum.IntEnum):
    """Stands for Sock Opt Level

    This is what should be passed as the "level" argument to
    getsockopt/setsockopt.

    """
    SOCKET = lib.SOL_SOCKET
    IP = lib.SOL_IP

class IP(enum.IntEnum):
    RECVERR = lib.IP_RECVERR
    PKTINFO = lib.IP_PKTINFO
    MULTICAST_TTL = lib.IP_MULTICAST_TTL
    MTU_DISCOVER = lib.IP_MTU_DISCOVER
    PMTUDISC_DONT = lib.IP_PMTUDISC_DONT

@dataclass
class Inet6Address(Address):
    port: int
    addr: ipaddress.IPv6Address
    flowinfo: int = 0
    scope_id: int = 0

    def __post_init__(self) -> None:
        self.addr = ipaddress.IPv6Address(self.addr)

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct sockaddr_in6*',
                         (AF.INET6, socket.htons(self.port), self.flowinfo, (b'',), self.scope_id))
        struct.sin6_addr.s6_addr = self.addr.packed
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='Inet6Address')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        struct = ffi.cast('struct sockaddr_in6*', ffi.from_buffer(data))
        return cls(socket.ntohs(struct.sin6_port), ipaddress.IPv6Address(bytes(struct.sin6_addr.s6_addr)),
                   struct.sin6_flowinfo, struct.sin6_scope_id)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_in6')
