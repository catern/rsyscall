"""`#include <net/if.h>`

The associated manpage is netdevice(7)

"""
from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.sys.socket import Sockaddr
from rsyscall.struct import Struct
import enum
import typing as t

__all__ = [
    "IFF",
    "SIOC",
    "TUNSETIFF",
    "Ifreq",
]

TUNSETIFF: int = lib.TUNSETIFF

class SIOC(enum.IntEnum):
    "ioctl request codes for network device configuration"
    GIFNAME = lib.SIOCGIFNAME # get iface name
    SIFLINK = lib.SIOCSIFLINK # set iface channel
    GIFCONF = lib.SIOCGIFCONF # get iface list
    GIFFLAGS = lib.SIOCGIFFLAGS # get flags
    SIFFLAGS = lib.SIOCSIFFLAGS # set flags
    GIFADDR = lib.SIOCGIFADDR # get PA address
    SIFADDR = lib.SIOCSIFADDR # set PA address
    GIFDSTADDR = lib.SIOCGIFDSTADDR # get remote PA address
    SIFDSTADDR = lib.SIOCSIFDSTADDR # set remote PA address
    GIFBRDADDR = lib.SIOCGIFBRDADDR # get broadcast PA address
    SIFBRDADDR = lib.SIOCSIFBRDADDR # set broadcast PA address
    GIFNETMASK = lib.SIOCGIFNETMASK # get network PA mask
    SIFNETMASK = lib.SIOCSIFNETMASK # set network PA mask
    GIFMETRIC = lib.SIOCGIFMETRIC # get metric
    SIFMETRIC = lib.SIOCSIFMETRIC # set metric
    GIFMEM = lib.SIOCGIFMEM # get memory address (BSD)
    SIFMEM = lib.SIOCSIFMEM # set memory address (BSD)
    GIFMTU = lib.SIOCGIFMTU # get MTU size
    SIFMTU = lib.SIOCSIFMTU # set MTU size
    SIFNAME = lib.SIOCSIFNAME # set interface name
    SIFHWADDR = lib.SIOCSIFHWADDR # set hardware address
    GIFENCAP = lib.SIOCGIFENCAP # get/set encapsulations
    SIFENCAP = lib.SIOCSIFENCAP
    GIFHWADDR = lib.SIOCGIFHWADDR # Get hardware address
    GIFSLAVE = lib.SIOCGIFSLAVE # Driver slaving support
    SIFSLAVE = lib.SIOCSIFSLAVE
    ADDMULTI = lib.SIOCADDMULTI # Multicast address lists
    DELMULTI = lib.SIOCDELMULTI
    GIFINDEX = lib.SIOCGIFINDEX # name -> if_index mapping
    SIFPFLAGS = lib.SIOCSIFPFLAGS # set/get extended flags set
    GIFPFLAGS = lib.SIOCGIFPFLAGS
    DIFADDR = lib.SIOCDIFADDR # delete PA address
    SIFHWBROADCAST = lib.SIOCSIFHWBROADCAST # set hardware broadcast addr
    GIFCOUNT = lib.SIOCGIFCOUNT # get number of devices

class IFF(enum.IntFlag):
    """Flags which can be set in Ifreq.flags

    These flags overlap; different sets of flags are used by different
    operations.

    """
    NONE        = 0
    ## device flags, from SIOC{G,S}IFFLAGS
    UP          = lib.IFF_UP          # Interface is running.
    BROADCAST   = lib.IFF_BROADCAST   # Valid broadcast address set.
    DEBUG       = lib.IFF_DEBUG       # Internal debugging flag.
    LOOPBACK    = lib.IFF_LOOPBACK    # Interface is a loopback interface.
    POINTOPOINT = lib.IFF_POINTOPOINT # Interface is a point-to-point link.
    RUNNING     = lib.IFF_RUNNING     # Resources allocated.
    NOARP       = lib.IFF_NOARP       # No arp protocol, L2 destination address not set.
    PROMISC     = lib.IFF_PROMISC     # Interface is in promiscuous mode.
    NOTRAILERS  = lib.IFF_NOTRAILERS  # Avoid use of trailers.
    ALLMULTI    = lib.IFF_ALLMULTI    # Receive all multicast packets.
    MASTER      = lib.IFF_MASTER      # Master of a load balancing bundle.
    SLAVE       = lib.IFF_SLAVE       # Slave of a load balancing bundle.
    MULTICAST   = lib.IFF_MULTICAST   # Supports multicast
    PORTSEL     = lib.IFF_PORTSEL     # Is able to select media type via ifmap.
    AUTOMEDIA   = lib.IFF_AUTOMEDIA   # Auto media selection active.
    DYNAMIC     = lib.IFF_DYNAMIC     # The addresses are lost when the interface goes down.
    # glibc doesn't have these in its headers for some reason
    # LOWER_UP    = lib.IFF_LOWER_UP    # Driver signals L1 up (since Linux 2.6.17)
    # DORMANT     = lib.IFF_DORMANT     # Driver signals dormant (since Linux 2.6.17)
    # ECHO        = lib.IFF_ECHO        # Echo sent packets (since Linux 2.6.25)
    ## TUNSETIFF flags
    TUN         = lib.IFF_TUN
    TAP         = lib.IFF_TAP
    NO_PI       = lib.IFF_NO_PI

class CStringField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> str:
        data = bytes(ffi.buffer(getattr(instance.cffi, self.name)))
        try:
            valid_data = data[:data.index(b'\0')]
        except ValueError:
            valid_data = data
        return valid_data.decode()

    def __set__(self, instance, value: str) -> None:
        setattr(instance.cffi, self.name, value.encode() + b"\0")

class IntField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> int:
        return getattr(instance.cffi, self.name)

    def __set__(self, instance, value: int) -> None:
        setattr(instance.cffi, self.name, value)

class AddressField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> Sockaddr:
        data_bytes = bytes(ffi.buffer(ffi.addressof(instance.cffi, self.name)))
        return Sockaddr.from_bytes(data_bytes)

    def __set__(self, instance, value: Sockaddr) -> None:
        data_bytes = value.to_bytes()
        ffi.memmove(ffi.addressof(instance.cffi, self.name),
                    ffi.from_buffer(data_bytes), len(data_bytes))

class IFFField:
    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, instance, owner) -> IFF:
        return IFF(getattr(instance.cffi, self.name))

    def __set__(self, instance, value: IFF) -> None:
        setattr(instance.cffi, self.name, value)

class Ifreq(Struct):
    """Representation of "struct ifreq"

    We have to be somewhat careful in how we represent this, since this struct
    is one big union, plus ifr_name which can be unset anyway.

    The way we handle this is, all the fields on this class are properties which
    extract some specific field from the union, stored as a cffi type.

    """
    name = CStringField("ifr_name")
    addr = AddressField("ifr_addr")
    ifindex = IntField("ifr_ifindex")
    flags = IFFField("ifr_flags")
    
    def __init__(self, name: str=None, *, addr: Sockaddr=None, flags: IFF=None, cffi=None) -> None:
        if cffi is None:
            cffi = ffi.new('struct ifreq*')
        self.cffi = cffi
        if name is not None:
            self.name = name
        if addr is not None:
            self.addr = addr
        if flags is not None:
            self.flags = flags

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(self.cffi))

    T = t.TypeVar('T', bound='Ifreq')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        if len(data) != cls.sizeof():
            raise Exception("data length", len(data),
                            "doesn't match actual length of struct ifreq", cls.sizeof())
        cffi = ffi.new('struct ifreq*')
        ffi.memmove(cffi, ffi.from_buffer(data), cls.sizeof())
        return cls(cffi=cffi)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct ifreq')

    def __str__(self) -> str:
        if self.name:
            return f"Ifreq({self.name}, ...)"
        else:
            # if it's an empty string, indicate that there's no name
            return "Ifreq(<no interface name>, ...)"


#### Tests ####
from unittest import TestCase
from rsyscall.netinet.ip import SockaddrIn
class TestIf(TestCase):
    def test_ifreq(self) -> None:
        initial = Ifreq()
        initial.name = "hello"
        initial.addr = SockaddrIn(42, "127.0.0.1")
        output = Ifreq.from_bytes(initial.to_bytes())
        self.assertEqual(initial.name, output.name)
        addr = t.cast(SockaddrIn, initial.addr.parse())
        self.assertIsInstance(addr, SockaddrIn)
        self.assertEqual(initial.addr.port, addr.port)
        self.assertEqual(initial.addr.addr, addr.addr)
