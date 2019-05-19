from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import typing as t
import enum
import socket
from rsyscall.struct import Struct, FixedSerializer, Serializable, Serializer, HasSerializer, FixedSize
import contextlib
import abc
import struct
import rsyscall.near as near
if t.TYPE_CHECKING:
    from rsyscall.handle import Pointer, WrittenPointer, FileDescriptor, Task
else:
    FileDescriptor = object
from rsyscall.sys.uio import IovecList

__all__ = [
    "AF",
    "Address",
    "SOCK",
    "SOL",
    "SO",
    "Socketpair",
    "Sockbuf",
    "CmsgSCMRights",
    "CmsgList",
    "SendMsghdr",
    "RecvMsghdr",
    "SendmsgFlags",
    "RecvmsgFlags",
    "MsghdrFlags",
]

T = t.TypeVar('T')
class AF(enum.IntEnum):
    UNIX = socket.AF_UNIX
    NETLINK = socket.AF_NETLINK
    INET = socket.AF_INET
    INET6 = socket.AF_INET6

class SHUT(enum.IntEnum):
    RD = socket.SHUT_RD
    WR = socket.SHUT_WR
    RDWR = socket.SHUT_RDWR

class Address(Struct):
    """This is just an interface to indicate different kinds of sockaddrs.

    We don't call this "Sockaddr" because that's a real struct,
    distinct from this class.

    """
    family: AF
    @classmethod
    def check_family(cls, family: AF) -> None:
        if cls.family != family:
            raise Exception("sa_family should be", cls.family, "is instead", family)

T_addr = t.TypeVar('T_addr', bound='Address')

family_to_class: t.Dict[AF, t.Type[Address]] = {}
def _register_sockaddr(sockaddr: t.Type[Address]) -> None:
    if sockaddr.family in family_to_class:
        raise Exception("tried to register sockaddr", sockaddr, "for family", sockaddr.family,
                        "but there's already a class registered for that family:",
                        family_to_class[sockaddr.family])
    family_to_class[sockaddr.family] = sockaddr

class SOCK(enum.IntFlag):
    # socket kinds
    DGRAM = socket.SOCK_DGRAM
    STREAM = socket.SOCK_STREAM
    RAW = socket.SOCK_RAW
    # flags that can be or'd in
    CLOEXEC = socket.SOCK_CLOEXEC
    NONBLOCK = socket.SOCK_NONBLOCK

class SOL(enum.IntEnum):
    """Stands for Sock Opt Level

    This is what should be passed as the "level" argument to
    getsockopt/setsockopt.

    """
    SOCKET = lib.SOL_SOCKET
    IP = lib.SOL_IP

class SO(enum.IntEnum):
    ERROR = lib.SO_ERROR

class SCM(enum.IntEnum):
    RIGHTS = socket.SCM_RIGHTS

@dataclass
class GenericSockaddr(Address):
    family: AF
    data: bytes

    @classmethod
    def check_family(cls, family: AF) -> None:
        if cls.family != family:
            raise Exception("sa_family should be", cls.family, "is instead", family)

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('sa_family_t*', self.family))) + self.data

    T = t.TypeVar('T', bound='GenericSockaddr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T: # type: ignore
        family = ffi.cast('sa_family_t*', ffi.from_buffer(data))
        rest = data[ffi.sizeof('sa_family_t'):]
        return cls(
            family=AF(family[0]),
            data=rest
        )

    @classmethod
    def sizeof(cls) -> int:
        # this is the maximum size of a sockaddr
        return ffi.sizeof('struct sockaddr_storage')

    def parse(self) -> Address:
        cls = family_to_class[self.family]
        return cls.from_bytes(self.to_bytes())

@dataclass
class Sockbuf(t.Generic[T], HasSerializer):
    buf: Pointer[T]
    buf_rest: t.Optional[Pointer[T]] = None

    def get_self_serializer(self, task: Task) -> SockbufSerializer[T]:
        return SockbufSerializer(self.buf)

class SockbufSerializer(t.Generic[T], Serializer[Sockbuf[T]]):
    def __init__(self, buf: Pointer[T]) -> None:
        self.buf = buf

    def to_bytes(self, val: Sockbuf) -> bytes:
        return bytes(ffi.buffer(ffi.new('socklen_t*', val.buf.bytesize())))

    def from_bytes(self, data: bytes) -> Sockbuf[T]:
        struct = ffi.cast('socklen_t*', ffi.from_buffer(data))
        socklen = struct[0]
        if socklen > self.buf.bytesize():
            raise Exception("not enough buffer space to read socket, need", socklen)
        valid, rest = self.buf.split(socklen)
        return Sockbuf(valid, rest)


#### socketpair stuff

T_socketpair = t.TypeVar('T_socketpair', bound='Socketpair')
@dataclass
class Socketpair(FixedSize):
    first: FileDescriptor
    second: FileDescriptor

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fdpair')

    @classmethod
    def get_serializer(cls: t.Type[T_socketpair], task: Task) -> Serializer[T_socketpair]:
        return SocketpairSerializer(cls, task)

@dataclass
class SocketpairSerializer(Serializer[T_socketpair]):
    cls: t.Type[T_socketpair]
    task: Task

    def to_bytes(self, pair: T_socketpair) -> bytes:
        struct = ffi.new('struct fdpair*', (pair.first, pair.second))
        return bytes(ffi.buffer(struct))

    def from_bytes(self, data: bytes) -> T_socketpair:
        struct = ffi.cast('struct fdpair const*', ffi.from_buffer(data))
        def make(n: int) -> FileDescriptor:
            return self.task.make_fd_handle(near.FileDescriptor(int(n)))
        return self.cls(make(struct.first), make(struct.second))


#### sendmsg/recvmsg stuff

class SendmsgFlags(enum.IntFlag):
    NONE = 0

class RecvmsgFlags(enum.IntFlag):
    NONE = 0

class MsghdrFlags(enum.IntFlag):
    NONE = 0
    CTRUNC = lib.MSG_CTRUNC

T_cmsg = t.TypeVar('T_cmsg', bound='Cmsg')
class Cmsg(FixedSerializer):
    @abc.abstractmethod
    def to_data(self) -> bytes: ...
    @abc.abstractmethod
    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None: ...
    @classmethod
    @abc.abstractmethod
    def from_data(cls: t.Type[T], task: Task, data: bytes) -> T: ...
    @classmethod
    @abc.abstractmethod
    def level(cls: t.Type[T]) -> SOL: ...
    @classmethod
    @abc.abstractmethod
    def type(cls: t.Type[T]) -> int: ...

    @classmethod
    def get_serializer(cls: t.Type[T_cmsg], task: Task) -> Serializer[T_cmsg]:
        return CmsgSerializer(cls, task)

class CmsgSerializer(Serializer[T_cmsg]):
    def __init__(self, cls: t.Type[T_cmsg], task: Task) -> None:
        self.cls = cls
        self.task = task

    def to_bytes(self, val: T_cmsg) -> bytes:
        if not isinstance(val, self.cls):
            raise Exception("Serializer for", self.cls,
                            "had to_bytes called on different type", val)
        data = val.to_data()
        header = bytes(ffi.buffer(ffi.new('struct cmsghdr*', {
            "cmsg_len": ffi.sizeof('struct cmsghdr') + len(data),
            "cmsg_level": val.level(),
            "cmsg_type": val.type(),
        })))
        return header + data

    def from_bytes(self, data: bytes) -> T_cmsg:
        record = ffi.cast('struct cmsghdr*', ffi.from_buffer(data))
        if record.cmsg_level != self.cls.level():
            raise Exception("serializer for level", self.cls.level(),
                            "got message for level", record.cmsg_level)
        if record.cmsg_type != self.cls.type():
            raise Exception("serializer for type", self.cls.type(),
                            "got message for type", record.cmsg_type)
        return self.cls.from_data(self.task, data[ffi.sizeof('struct cmsghdr'):record.cmsg_len])

import array
class CmsgSCMRights(Cmsg, t.List[FileDescriptor]):
    def to_data(self) -> bytes:
        return array.array('i', (int(fd.near) for fd in self)).tobytes()
    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None:
        for fd in self:
            stack.enter_context(fd.borrow(task))

    T = t.TypeVar('T', bound='CmsgSCMRights')
    @classmethod
    def from_data(cls: t.Type[T], task: Task, data: bytes) -> T:
        fds = [near.FileDescriptor(fd) for fd, in struct.Struct('i').iter_unpack(data)]
        return cls([task.make_fd_handle(fd) for fd in fds])

    @classmethod
    def level(cls) -> SOL:
        return SOL.SOCKET
    @classmethod
    def type(cls) -> int:
        return SCM.RIGHTS

T_cmsglist = t.TypeVar('T_cmsglist', bound='CmsgList')
class CmsgList(t.List[Cmsg], FixedSerializer):
    @classmethod
    def get_serializer(cls: t.Type[T_cmsglist], task: Task) -> Serializer[T_cmsglist]:
        return CmsgListSerializer(cls, task)

    def borrow_with(self, stack: contextlib.ExitStack, task: Task) -> None:
        for cmsg in self:
            cmsg.borrow_with(stack, task)

class CmsgListSerializer(Serializer[T_cmsglist]):
    def __init__(self, cls: t.Type[T_cmsglist], task: Task) -> None:
        self.cls = cls
        self.task = task

    def to_bytes(self, val: T_cmsglist) -> bytes:
        ret = b""
        for cmsg in val:
            # TODO is this correct alignment/padding???
            # I don't think so...
            ret += cmsg.get_serializer(self.task).to_bytes(cmsg)
        return ret

    def from_bytes(self, data: bytes) -> T_cmsglist:
        entries = []
        while len(data) > 0:
            record = ffi.cast('struct cmsghdr*', ffi.from_buffer(data))
            record_data = data[:record.cmsg_len]
            level = SOL(record.cmsg_level)
            if level == SOL.SOCKET and record.cmsg_type == int(SCM.RIGHTS):
                entries.append(CmsgSCMRights.get_serializer(self.task).from_bytes(record_data))
            else:
                raise Exception("unknown cmsg level/type sorry", level, type)
            data = data[record.cmsg_len:]
        return self.cls(entries)

@dataclass
class SendMsghdr(Serializable):
    name: t.Optional[WrittenPointer[Address]]
    iov: WrittenPointer[IovecList]
    control: t.Optional[WrittenPointer[CmsgList]]

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct msghdr*', {
            "msg_name": ffi.cast('void*', int(self.name.near)) if self.name else ffi.NULL,
            "msg_namelen": self.name.bytesize() if self.name else 0,
            "msg_iov": ffi.cast('void*', int(self.iov.near)),
            "msg_iovlen": len(self.iov.value),
            "msg_control": ffi.cast('void*', int(self.control.near)) if self.control else ffi.NULL,
            "msg_controllen": self.control.bytesize() if self.control else 0,
            "msg_flags": 0,
        })))

    T = t.TypeVar('T', bound='SendMsghdr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("can't get pointer handles from raw bytes")

@dataclass
class RecvMsghdr(Serializable):
    name: t.Optional[Pointer[Address]]
    iov: WrittenPointer[IovecList]
    control: t.Optional[Pointer[CmsgList]]

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct msghdr*', {
            "msg_name": ffi.cast('void*', int(self.name.near)) if self.name else ffi.NULL,
            "msg_namelen": self.name.bytesize() if self.name else 0,
            "msg_iov": ffi.cast('void*', int(self.iov.near)),
            "msg_iovlen": len(self.iov.value),
            "msg_control": ffi.cast('void*', int(self.control.near)) if self.control else ffi.NULL,
            "msg_controllen": self.control.bytesize() if self.control else 0,
            "msg_flags": 0,
        })))

    T = t.TypeVar('T', bound='RecvMsghdr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("can't get pointer handles from raw bytes")

    def to_out(self, ptr: Pointer[RecvMsghdr]) -> Pointer[RecvMsghdrOut]:
        # what a mouthful
        serializer = RecvMsghdrOutSerializer(self.name, self.control)
        return ptr._reinterpret(serializer)

@dataclass
class RecvMsghdrOut:
    name: t.Optional[Pointer[Address]]
    control: t.Optional[Pointer[CmsgList]]
    flags: MsghdrFlags
    # the _rest fields are the invalid, unused parts of the buffers;
    # almost everyone can ignore these.
    name_rest: t.Optional[Pointer[Address]]
    control_rest: t.Optional[Pointer[CmsgList]]

@dataclass
class RecvMsghdrOutSerializer(Serializer[RecvMsghdrOut]):
    name: t.Optional[Pointer[Address]]
    control: t.Optional[Pointer[CmsgList]]

    def to_bytes(self, x: RecvMsghdrOut) -> bytes:
        raise Exception("not going to bother implementing this")

    def from_bytes(self, data: bytes) -> RecvMsghdrOut:
        struct = ffi.cast('struct msghdr*', ffi.from_buffer(data))
        if self.name is None:
            name: t.Optional[Pointer[Address]] = None
            name_rest: t.Optional[Pointer[Address]] = None
        else:
            name, name_rest = self.name.split(struct.msg_namelen)
        if self.control is None:
            control: t.Optional[Pointer[CmsgList]] = None
            control_rest: t.Optional[Pointer[CmsgList]] = None
        else:
            control, control_rest = self.control.split(struct.msg_controllen)
        flags = MsghdrFlags(struct.msg_flags)
        return RecvMsghdrOut(name, control, flags, name_rest, control_rest)


#### Tests ####
from unittest import TestCase
class TestSocket(TestCase):
    pass
