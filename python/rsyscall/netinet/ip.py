from rsyscall._raw import ffi, lib # type: ignore
import enum
import socket

# ip.h is a superset of in.h
from rsyscall.netinet.in_ import SockaddrIn, SockaddrIn6

class IPPROTO(enum.IntEnum):
    ICMPV6 = socket.IPPROTO_ICMPV6

class IP(enum.IntEnum):
    RECVERR = lib.IP_RECVERR
    PKTINFO = lib.IP_PKTINFO
    MULTICAST_TTL = lib.IP_MULTICAST_TTL
    MTU_DISCOVER = lib.IP_MTU_DISCOVER
    PMTUDISC_DONT = lib.IP_PMTUDISC_DONT
