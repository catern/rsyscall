"`#include <linux/netlink.h>`"
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import Sockaddr, AF, _register_sockaddr
import typing as t
import enum
from dataclasses import dataclass

__all__ = [
    "NETLINK",
    "SockaddrNl",
]

class NETLINK(enum.IntEnum):
    ROUTE = lib.NETLINK_ROUTE

@dataclass
class SockaddrNl(Sockaddr):
    # not an actual process pid, but rather "port id", which is unique per netlink socket
    pid: int
    groups: int
    family = AF.NETLINK

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct sockaddr_nl*', (AF.NETLINK, 0, self.pid, self.groups))
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='SockaddrNl')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        struct = ffi.cast('struct sockaddr_nl*', ffi.from_buffer(data))
        cls.check_family(AF(struct.nl_family))
        return cls(struct.nl_pid, struct.nl_groups)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_nl')
_register_sockaddr(SockaddrNl)
