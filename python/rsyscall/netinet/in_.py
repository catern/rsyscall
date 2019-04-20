from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import Address, AF
import ipaddress
import socket
import typing as t
from dataclasses import dataclass

class SockaddrIn(Address):
    addrlen: int = ffi.sizeof('struct sockaddr_in')
    def __init__(self, port: int, addr: t.Union[int, ipaddress.IPv4Address]) -> None:
        # these are in host byte order, of course
        self.port = port
        self.addr = ipaddress.IPv4Address(addr)

    T = t.TypeVar('T', bound='SockaddrIn')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct sockaddr_in*', ffi.from_buffer(data))
        if struct.sin_family != AF.INET:
            raise Exception("sin_family must be", AF.INET, "is instead", struct.sin_family)
        return cls(socket.ntohs(struct.sin_port), socket.ntohl(struct.sin_addr.s_addr))

    def to_bytes(self) -> bytes:
        addr = ffi.new('struct sockaddr_in*', (AF.INET, socket.htons(self.port), (socket.htonl(int(self.addr)),)))
        return ffi.buffer(addr)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_in')

    def addr_as_string(self) -> str:
        "Returns the addr portion of this address in 127.0.0.1 form"
        return str(self.addr)

    def __str__(self) -> str:
        return f"SockaddrIn({self.addr_as_string()}:{self.port})"

@dataclass
class SockaddrIn6(Address):
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

    T = t.TypeVar('T', bound='SockaddrIn6')
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

