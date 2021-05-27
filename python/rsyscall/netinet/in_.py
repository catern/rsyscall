"`#include <netinet/in.h>`"
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import Sockaddr, AF, _register_sockaddr
import ipaddress
import socket
import typing as t
from dataclasses import dataclass

__all__ = [
    'SockaddrIn',
    'SockaddrIn6',
]

@dataclass(frozen=True)
class SockaddrIn(Sockaddr):
    """Representation of struct sockaddr_in

    The port is in totally-normal host byte order, even though with the real
    struct sockaddr_in, the port (and address) would be in network byte
    order. That's just an encoding quirk of C, not something we want to copy.

    """
    port: int
    addr: ipaddress.IPv4Address
    family = AF.INET
    def __init__(self, port: int, addr: t.Union[str, int, ipaddress.IPv4Address]) -> None:
        # the dataclass is frozen so we have to use __setattr__
        object.__setattr__(self, 'port', port)
        object.__setattr__(self, 'addr', ipaddress.IPv4Address(addr))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_in*', (AF.INET, socket.htons(self.port), (socket.htonl(int(self.addr)),)))
        return bytes(ffi.buffer(addr))

    T = t.TypeVar('T', bound='SockaddrIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        struct = ffi.cast('struct sockaddr_in*', ffi.from_buffer(data))
        cls.check_family(AF(struct.sin_family))
        return cls(socket.ntohs(struct.sin_port), socket.ntohl(struct.sin_addr.s_addr))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_in')

    def addr_as_string(self) -> str:
        "Returns the addr portion of this address in 127.0.0.1 form"
        return str(self.addr)

    def __str__(self) -> str:
        return f"SockaddrIn({self.addr_as_string()}:{self.port})"

    def __repr__(self) -> str:
        return str(self)
_register_sockaddr(SockaddrIn)


class SockaddrIn6(Sockaddr):
    "Representation of struct sockaddr_in6"
    family = AF.INET6
    def __init__(self, port: int, addr: t.Union[str, int, ipaddress.IPv6Address],
                 flowinfo: int=0, scope_id: int=0) -> None:
        # these are in host byte order, of course
        self.port = port
        self.addr = ipaddress.IPv6Address(addr)
        self.flowinfo = flowinfo
        self.scope_id = scope_id

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct sockaddr_in6*',
                         (AF.INET6, socket.htons(self.port), self.flowinfo, (b'',), self.scope_id))
        struct.sin6_addr.s6_addr = self.addr.packed
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='SockaddrIn6')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        struct = ffi.cast('struct sockaddr_in6*', ffi.from_buffer(data))
        cls.check_family(AF(struct.sin6_family))
        return cls(socket.ntohs(struct.sin6_port), ipaddress.IPv6Address(bytes(struct.sin6_addr.s6_addr)),
                   struct.sin6_flowinfo, struct.sin6_scope_id)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_in6')

    def __str__(self) -> str:
        return f"SockaddrIn6({self.addr}:{self.port})"

    def __repr__(self) -> str:
        return str(self)
_register_sockaddr(SockaddrIn6)


#### Tests ####
from unittest import TestCase
class TestIn(TestCase):
    def test_sockaddrin(self) -> None:
        initial = SockaddrIn(42, "127.0.0.1")
        output = SockaddrIn.from_bytes(initial.to_bytes())
        self.assertEqual(initial.port, output.port)
        self.assertEqual(initial.addr, output.addr)
        from rsyscall.sys.socket import SockaddrStorage
        out = SockaddrStorage.from_bytes(initial.to_bytes()).parse()
        self.assertEqual(initial.port, output.port)
        self.assertEqual(initial.addr, output.addr)

    def test_sockaddrIn6(self) -> None:
        initial = SockaddrIn6(42, "34:12::19:9a")
        output = SockaddrIn6.from_bytes(initial.to_bytes())
        self.assertEqual(initial.port, output.port)
        self.assertEqual(initial.addr, output.addr)
        from rsyscall.sys.socket import SockaddrStorage
        out = SockaddrStorage.from_bytes(initial.to_bytes()).parse()
        self.assertEqual(initial.port, output.port)
        self.assertEqual(initial.addr, output.addr)
        
