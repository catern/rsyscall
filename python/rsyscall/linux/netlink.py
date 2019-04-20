from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import Address
import typing as t
from dataclasses import dataclass

@dataclass
class SockaddrNl(Address):
    # not an actual process pid, but rather "port id", which is unique per netlink socket
    pid: int
    groups: int

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct sockaddr_nl*', (lib.AF_NETLINK, 0, self.pid, self.groups))
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='SockaddrNl')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) < cls.sizeof():
            raise Exception("data too small", data)
        struct = ffi.cast('struct sockaddr_nl*', ffi.from_buffer(data))
        return cls(struct.nl_pid, struct.nl_groups)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_nl')
