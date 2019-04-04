import socket
from rsyscall._raw import lib # type: ignore
import enum

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
