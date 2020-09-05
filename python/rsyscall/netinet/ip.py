"`#include <netinet/ip.h>`"
from rsyscall._raw import ffi, lib # type: ignore
import enum

# ip.h is a superset of in.h
from rsyscall.netinet.in_ import SockaddrIn, SockaddrIn6
__all__ = [
    "SockaddrIn",
    "SockaddrIn6",
    "IPPROTO",
    "IP",
]

class IPPROTO(enum.IntEnum):
    "Used for a variety of things"
    ICMPV6 = lib.IPPROTO_ICMPV6

class IP(enum.IntEnum):
    "Mostly for socket options"
    RECVERR = lib.IP_RECVERR
    PKTINFO = lib.IP_PKTINFO
    MULTICAST_TTL = lib.IP_MULTICAST_TTL
    MTU_DISCOVER = lib.IP_MTU_DISCOVER
    PMTUDISC_DONT = lib.IP_PMTUDISC_DONT
