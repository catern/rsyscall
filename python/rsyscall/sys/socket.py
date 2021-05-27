"`#include <sys/socket.h>`"
from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
import typing as t
import enum
from rsyscall.struct import Struct, FixedSerializer, Serializable, Serializer, HasSerializer, FixedSize
import contextlib
import abc
import struct
import rsyscall.near.types as near
from rsyscall.handle.pointer import Pointer, WrittenPointer, ReadablePointer, LinearPointer
if t.TYPE_CHECKING:
    from rsyscall.handle import FileDescriptor, Task
else:
    FileDescriptor = object
from rsyscall.sys.uio import IovecList

__all__ = [
    "AF",
    "SHUT",
    "Sockaddr",
    "SockaddrStorage",
    "SOCK",
    "SOL",
    "SO",
    "MSG",
    "Socketpair",
    "Sockbuf",
    "CmsgSCMRights",
    "CmsgList",
    "SendMsghdr",
    "RecvMsghdr",
    "RecvMsghdrOut",
    "SendmsgFlags",
    "RecvmsgFlags",
    "MsghdrFlags",
    "SocketTask",
    "SocketFileDescriptor",
]

T = t.TypeVar('T')
class AF(enum.IntEnum):
    UNIX = lib.AF_UNIX
    NETLINK = lib.AF_NETLINK
    INET = lib.AF_INET
    INET6 = lib.AF_INET6

class SHUT(enum.IntEnum):
    RD = lib.SHUT_RD
    WR = lib.SHUT_WR
    RDWR = lib.SHUT_RDWR

class MSG(enum.IntFlag):
    NONE = 0
    # send flags
    CONFIRM = lib.MSG_CONFIRM
    DONTROUTE = lib.MSG_DONTROUTE
    EOR = lib.MSG_EOR
    MORE = lib.MSG_MORE
    NOSIGNAL = lib.MSG_NOSIGNAL
    # recv flags
    CMSG_CLOEXEC = lib.MSG_CMSG_CLOEXEC
    ERRQUEUE = lib.MSG_ERRQUEUE
    PEEK = lib.MSG_PEEK
    TRUNC = lib.MSG_TRUNC
    WAITALL = lib.MSG_WAITALL
    # both
    DONTWAIT = lib.MSG_DONTWAIT
    OOB = lib.MSG_OOB

family_to_class: t.Dict[AF, t.Type[Sockaddr]] = {}
def _register_sockaddr(sockaddr: t.Type[Sockaddr]) -> None:
    if sockaddr.family in family_to_class:
        raise Exception("tried to register sockaddr", sockaddr, "for family", sockaddr.family,
                        "but there's already a class registered for that family:",
                        family_to_class[sockaddr.family])
    family_to_class[sockaddr.family] = sockaddr

class Sockaddr(Struct):
    """struct sockaddr. This is not really useful to allocate on its own; you want the derived classes.

    """
    def __init__(self, family: AF, data: bytes) -> None:
        self.family = family
        self.data = data

    @classmethod
    def check_family(cls, family: AF) -> None:
        if cls.family != family:
            raise Exception("sa_family should be", cls.family, "is instead", family)

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct sockaddr*', (self.family, self.data))
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='Sockaddr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct sockaddr*', ffi.from_buffer(data))
        return cls(struct.sa_family, bytes(ffi.buffer(struct.sa_data)))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr')

    def parse(self) -> Sockaddr:
        "Using the family field, return the correct Sockaddr type that this actually contains."
        cls = family_to_class[self.family]
        return cls.from_bytes(self.to_bytes())

T_sockaddr = t.TypeVar('T_sockaddr', bound='Sockaddr')

class SOCK(enum.IntFlag):
    NONE = 0
    # socket kinds
    DGRAM = lib.SOCK_DGRAM
    STREAM = lib.SOCK_STREAM
    SEQPACKET = lib.SOCK_SEQPACKET
    RAW = lib.SOCK_RAW
    # flags that can be or'd in
    CLOEXEC = lib.SOCK_CLOEXEC
    NONBLOCK = lib.SOCK_NONBLOCK

class SOL(enum.IntEnum):
    """Stands for Sock Opt Level

    This is what should be passed as the "level" argument to
    getsockopt/setsockopt.

    """
    SOCKET = lib.SOL_SOCKET
    IP = lib.SOL_IP

class SO(enum.IntEnum):
    ACCEPTCONN = lib.SO_ACCEPTCONN
    ATTACH_FILTER = lib.SO_ATTACH_FILTER
    ATTACH_BPF = lib.SO_ATTACH_BPF
    ATTACH_REUSEPORT_CBPF = lib.SO_ATTACH_REUSEPORT_CBPF
    ATTACH_REUSEPORT_EBPF = lib.SO_ATTACH_REUSEPORT_EBPF
    BINDTODEVICE = lib.SO_BINDTODEVICE
    BROADCAST = lib.SO_BROADCAST
    BSDCOMPAT = lib.SO_BSDCOMPAT
    DEBUG = lib.SO_DEBUG
    DETACH_FILTER = lib.SO_DETACH_FILTER
    DETACH_BPF = lib.SO_DETACH_BPF
    DOMAIN = lib.SO_DOMAIN
    ERROR = lib.SO_ERROR
    DONTROUTE = lib.SO_DONTROUTE
    INCOMING_CPU = lib.SO_INCOMING_CPU
    KEEPALIVE = lib.SO_KEEPALIVE
    LINGER = lib.SO_LINGER
    LOCK_FILTER = lib.SO_LOCK_FILTER
    MARK = lib.SO_MARK
    OOBINLINE = lib.SO_OOBINLINE
    PASSCRED = lib.SO_PASSCRED
    PEEK_OFF = lib.SO_PEEK_OFF
    PEERCRED = lib.SO_PEERCRED
    PRIORITY = lib.SO_PRIORITY
    PROTOCOL = lib.SO_PROTOCOL
    RCVBUF = lib.SO_RCVBUF
    RCVBUFFORCE = lib.SO_RCVBUFFORCE
    RCVLOWAT = lib.SO_RCVLOWAT
    SNDLOWAT = lib.SO_SNDLOWAT
    RCVTIMEO = lib.SO_RCVTIMEO
    SNDTIMEO = lib.SO_SNDTIMEO
    REUSEADDR = lib.SO_REUSEADDR
    REUSEPORT = lib.SO_REUSEPORT
    RXQ_OVFL = lib.SO_RXQ_OVFL
    SNDBUF = lib.SO_SNDBUF
    SNDBUFFORCE = lib.SO_SNDBUFFORCE
    TIMESTAMP = lib.SO_TIMESTAMP
    TYPE = lib.SO_TYPE
    BUSY_POLL = lib.SO_BUSY_POLL

class SCM(enum.IntEnum):
    RIGHTS = lib.SCM_RIGHTS

@dataclass
class SockaddrStorage(Sockaddr):
    "struct sockaddr_storage. Useful when dealing with sockets with unknown address families"
    family: AF
    data: bytes

    def to_bytes(self) -> bytes:
        # We can't just create a struct sockaddr_storage and turn the whole thing to bytes,
        # because that will pad the actually valid data with a bunch of trailing null bytes.
        # And we can't do that because the length of the valid data is semantically
        # meaningful for some socket addresses, such as sockaddr_un.
        return bytes(ffi.buffer(ffi.new('sa_family_t*', self.family))) + self.data

    T = t.TypeVar('T', bound='SockaddrStorage')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        # As with to_bytes, we can't just cast the bytes to a struct sockaddr_storage and read its data field,
        # because that would pad the data with a bunch of null bytes,
        # and would not preserve the length of the valid data
        family = ffi.cast('sa_family_t*', ffi.from_buffer(data))
        rest = data[ffi.sizeof('sa_family_t'):]
        return cls(
            family=AF(family[0]),
            data=rest
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct sockaddr_storage')

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
        return bytes(ffi.buffer(ffi.new('socklen_t*', val.buf.size())))

    def from_bytes(self, data: bytes) -> Sockbuf[T]:
        struct = ffi.cast('socklen_t*', ffi.from_buffer(data))
        socklen = struct[0]
        if socklen > self.buf.size():
            raise Exception("not enough buffer space to read socket, need", socklen)
        valid, rest = self.buf.readable_split(socklen)
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
    CMSG_CLOEXEC = lib.MSG_CMSG_CLOEXEC

class MsghdrFlags(enum.IntFlag):
    NONE = 0
    CTRUNC = lib.MSG_CTRUNC
    CMSG_CLOEXEC = lib.MSG_CMSG_CLOEXEC

T_cmsg = t.TypeVar('T_cmsg', bound='Cmsg')
class Cmsg(FixedSerializer):
    @abc.abstractmethod
    def to_data(self) -> bytes: ...
    @abc.abstractmethod
    def borrow_with(self, stack: contextlib.ExitStack, task: FileDescriptorTask) -> None: ...
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
        return array.array('i', (int(fd) for fd in self)).tobytes()
    def borrow_with(self, stack: contextlib.ExitStack, task: FileDescriptorTask) -> None:
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

    def borrow_with(self, stack: contextlib.ExitStack, task: FileDescriptorTask) -> None:
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
    name: t.Optional[WrittenPointer[Sockaddr]]
    iov: WrittenPointer[IovecList]
    control: t.Optional[WrittenPointer[CmsgList]]

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct msghdr*', {
            "msg_name": ffi.cast('void*', int(self.name.near)) if self.name else ffi.NULL,
            "msg_namelen": self.name.size() if self.name else 0,
            "msg_iov": ffi.cast('void*', int(self.iov.near)),
            "msg_iovlen": len(self.iov.value),
            "msg_control": ffi.cast('void*', int(self.control.near)) if self.control else ffi.NULL,
            "msg_controllen": self.control.size() if self.control else 0,
            "msg_flags": 0,
        })))

    T = t.TypeVar('T', bound='SendMsghdr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("can't get pointer handles from raw bytes")

@dataclass
class RecvMsghdr(Serializable):
    name: t.Optional[Pointer[Sockaddr]]
    iov: WrittenPointer[IovecList]
    control: t.Optional[Pointer[CmsgList]]

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct msghdr*', {
            "msg_name": ffi.cast('void*', int(self.name.near)) if self.name else ffi.NULL,
            "msg_namelen": self.name.size() if self.name else 0,
            "msg_iov": ffi.cast('void*', int(self.iov.near)),
            "msg_iovlen": len(self.iov.value),
            "msg_control": ffi.cast('void*', int(self.control.near)) if self.control else ffi.NULL,
            "msg_controllen": self.control.size() if self.control else 0,
            "msg_flags": 0,
        })))

    T = t.TypeVar('T', bound='RecvMsghdr')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        raise Exception("can't get pointer handles from raw bytes")

    def to_out(self, ptr: Pointer[RecvMsghdr]) -> Pointer[RecvMsghdrOut]:
        # what a mouthful
        serializer = RecvMsghdrOutSerializer(self.name, self.control)
        return ptr._reinterpret(serializer, RecvMsghdrOut)

@dataclass
class RecvMsghdrOut:
    name: t.Optional[ReadablePointer[Sockaddr]]
    control: t.Optional[LinearPointer[CmsgList]]
    flags: MsghdrFlags
    # the _rest fields are the invalid, unused parts of the buffers;
    # almost everyone can ignore these.
    name_rest: t.Optional[Pointer[Sockaddr]]
    control_rest: t.Optional[Pointer[CmsgList]]

@dataclass
class RecvMsghdrOutSerializer(Serializer[RecvMsghdrOut]):
    name: t.Optional[Pointer[Sockaddr]]
    control: t.Optional[Pointer[CmsgList]]

    def to_bytes(self, x: RecvMsghdrOut) -> bytes:
        raise Exception("not going to bother implementing this")

    def from_bytes(self, data: bytes) -> RecvMsghdrOut:
        struct = ffi.cast('struct msghdr*', ffi.from_buffer(data))
        if self.name is None:
            name: t.Optional[ReadablePointer[Sockaddr]] = None
            name_rest: t.Optional[Pointer[Sockaddr]] = None
        else:
            name, name_rest = self.name.readable_split(struct.msg_namelen)
        if self.control is None:
            control: t.Optional[Pointer[CmsgList]] = None
            control_rest: t.Optional[Pointer[CmsgList]] = None
        else:
            control, control_rest = self.control.readable_split(struct.msg_controllen)
        flags = MsghdrFlags(struct.msg_flags)
        return RecvMsghdrOut(name, control._linearize() if control else None, flags, name_rest, control_rest)

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask

T_fd = t.TypeVar('T_fd', bound='SocketFileDescriptor')
class SocketFileDescriptor(BaseFileDescriptor):
    async def bind(self, addr: WrittenPointer[Sockaddr]) -> None:
        """bind a name to a socket

        man: bind(2)
        """
        self._validate()
        with addr.borrow(self.task):
            try:
                await _bind(self.task.sysif, self.near, addr.near, addr.size())
            except PermissionError as exn:
                exn.filename = addr.value
                raise
            except FileNotFoundError as exn:
                exn.filename = addr.value
                raise

    async def connect(self, addr: WrittenPointer[Sockaddr]) -> None:
        self._validate()
        with addr.borrow(self.task):
            try:
                await _connect(self.task.sysif, self.near, addr.near, addr.size())
            except OSError as exn:
                exn.filename = self
                if hasattr(addr, 'value'):
                    exn.filename2 = addr.value
                raise

    async def listen(self, backlog: int) -> None:
        self._validate()
        await _listen(self.task.sysif, self.near, backlog)

    async def getsockopt(self, level: int, optname: int, optval: WrittenPointer[Sockbuf[T]]) -> Pointer[Sockbuf[T]]:
        self._validate()
        with optval.borrow(self.task):
            with optval.value.buf.borrow(self.task):
                await _getsockopt(self.task.sysif, self.near,
                                  level, optname, optval.value.buf.near, optval.near)
        return optval

    async def setsockopt(self, level: int, optname: int, optval: Pointer) -> None:
        self._validate()
        with optval.borrow(self.task) as optval_n:
            await _setsockopt(self.task.sysif, self.near, level, optname, optval_n, optval.size())

    async def getsockname(self, addr: WrittenPointer[Sockbuf[T_sockaddr]]) -> Pointer[Sockbuf[T_sockaddr]]:
        self._validate()
        with addr.borrow(self.task) as addr_n:
            with addr.value.buf.borrow(self.task) as addrbuf_n:
                await _getsockname(self.task.sysif, self.near, addrbuf_n, addr_n)
        return addr

    async def getpeername(self, addr: WrittenPointer[Sockbuf[T_sockaddr]]) -> Pointer[Sockbuf[T_sockaddr]]:
        self._validate()
        with addr.borrow(self.task) as addr_n:
            with addr.value.buf.borrow(self.task) as addrbuf_n:
                await _getpeername(self.task.sysif, self.near, addrbuf_n, addr_n)
        return addr

    @t.overload
    async def accept(self: T_fd, flags: SOCK=SOCK.NONE) -> T_fd: ...
    @t.overload
    async def accept(self: T_fd, flags: SOCK, addr: WrittenPointer[Sockbuf[T_sockaddr]]
    ) -> t.Tuple[T_fd, WrittenPointer[Sockbuf[T_sockaddr]]]: ...

    async def accept(self: T_fd, flags: SOCK=SOCK.NONE,
                     addr: t.Optional[WrittenPointer[Sockbuf[T_sockaddr]]]=None
    ) -> t.Union[T_fd, t.Tuple[T_fd, WrittenPointer[Sockbuf[T_sockaddr]]]]:
        self._validate()
        flags |= SOCK.CLOEXEC
        if addr is None:
            fd = await _accept(self.task.sysif, self.near, None, None, flags)
            return self.task.make_fd_handle(fd)
        else:
            with addr.borrow(self.task):
                with addr.value.buf.borrow(self.task):
                    fd = await _accept(self.task.sysif, self.near,
                                       addr.value.buf.near, addr.near, flags)
                    return self.task.make_fd_handle(fd), addr

    async def shutdown(self, how: SHUT) -> None:
        self._validate()
        await _shutdown(self.task.sysif, self.near, how)

    async def sendmsg(self, msg: WrittenPointer[SendMsghdr], flags: SendmsgFlags=SendmsgFlags.NONE
    ) -> t.Tuple[IovecList, IovecList]:
        """send a message on a socket

        man: sendmsg(2)
        """
        with contextlib.ExitStack() as stack:
            stack.enter_context(msg.borrow(self.task))
            if msg.value.name:
                stack.enter_context(msg.value.name.borrow(self.task))
            if msg.value.control:
                stack.enter_context(msg.value.control.borrow(self.task))
                msg.value.control.value.borrow_with(stack, self.task)
            stack.enter_context(msg.value.iov.borrow(self.task))
            for iovec_elem in msg.value.iov.value:
                stack.enter_context(iovec_elem.borrow(self.task))
            ret = await _sendmsg(self.task.sysif, self.near, msg.near, flags)
        return msg.value.iov.value.split(ret)

    async def recvmsg(self, msg: WrittenPointer[RecvMsghdr], flags: RecvmsgFlags=RecvmsgFlags.NONE,
    ) -> t.Tuple[IovecList, IovecList, Pointer[RecvMsghdrOut]]:
        """receive a message from a socket

        man: recvmsg(2)
        """
        flags |= RecvmsgFlags.CMSG_CLOEXEC
        with contextlib.ExitStack() as stack:
            stack.enter_context(msg.borrow(self.task))
            if msg.value.name:
                stack.enter_context(msg.value.name.borrow(self.task))
            if msg.value.control:
                stack.enter_context(msg.value.control.borrow(self.task))
            stack.enter_context(msg.value.iov.borrow(self.task))
            for iovec_elem in msg.value.iov.value:
                stack.enter_context(iovec_elem.borrow(self.task))
            ret = await _recvmsg(self.task.sysif, self.near, msg.near, flags)
        valid, invalid = msg.value.iov.value.split(ret)
        return valid, invalid, msg.value.to_out(msg)

    async def recv(self, buf: Pointer[T], flags: MSG) -> t.Tuple[ReadablePointer[T], Pointer]:
        """receive a message from a socket

        man: recv(2)
        """
        self._validate()
        with buf.borrow(self.task) as buf_n:
            ret = await _recv(self.task.sysif, self.near, buf_n, buf.size(), flags)
            return buf.readable_split(ret)

    async def send(self, buf: Pointer[T], flags: MSG) -> t.Tuple[Pointer[T], Pointer]:
        """send a message on a socket

        man: send(2)
        """
        self._validate()
        with buf.borrow(self.task) as buf_n:
            ret = await _send(self.task.sysif, self.near, buf_n, buf.size(), flags)
            return buf.split(ret)

class SocketTask(FileDescriptorTask[T_fd]):
    async def socket(self, domain: AF, type: SOCK, protocol: int=0) -> T_fd:
        """create an endpoint for communication

        manpage: socket(2)
        """
        sockfd = await _socket(self.sysif, domain, type|SOCK.CLOEXEC, protocol)
        return self.make_fd_handle(sockfd)

    async def socketpair(self, domain: AF, type: SOCK, protocol: int,
                         sv: Pointer[Socketpair]) -> LinearPointer[Socketpair]:
        with sv.borrow(self) as sv_n:
            await _socketpair(self.sysif, domain, type|SOCK.CLOEXEC, protocol, sv_n)
            return sv._linearize()

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _socket(sysif: SyscallInterface,
                  domain: AF, type: SOCK, protocol: int) -> near.FileDescriptor:
    return near.FileDescriptor(await sysif.syscall(SYS.socket, domain, type, protocol))

async def _socketpair(sysif: SyscallInterface,
                      domain: AF, type: SOCK, protocol: int, sv: near.Address) -> None:
    await sysif.syscall(SYS.socketpair, domain, type, protocol, sv)

async def _bind(sysif: SyscallInterface, sockfd: near.FileDescriptor,
               addr: near.Address, addrlen: int) -> None:
    await sysif.syscall(SYS.bind, sockfd, addr, addrlen)

async def _connect(sysif: SyscallInterface, sockfd: near.FileDescriptor,
                   addr: near.Address, addrlen: int) -> None:
    await sysif.syscall(SYS.connect, sockfd, addr, addrlen)

async def _listen(sysif: SyscallInterface, sockfd: near.FileDescriptor,
                  backlog: int) -> None:
    await sysif.syscall(SYS.listen, sockfd, backlog)

async def _accept(sysif: SyscallInterface, sockfd: near.FileDescriptor,
                  addr: t.Optional[near.Address], addrlen: t.Optional[near.Address],
                  flags: SOCK) -> near.FileDescriptor:
    if addr is None:
        addr = 0 # type: ignore
    if addrlen is None:
        addrlen = 0 # type: ignore
    return near.FileDescriptor(await sysif.syscall(SYS.accept4, sockfd, addr, addrlen, flags))

async def _shutdown(sysif: SyscallInterface, sockfd: near.FileDescriptor, how: SHUT) -> None:
    await sysif.syscall(SYS.shutdown, sockfd, how)

async def _getsockname(sysif: SyscallInterface, sockfd: near.FileDescriptor,
                       addr: near.Address, addrlen: near.Address) -> None:
    await sysif.syscall(SYS.getsockname, sockfd, addr, addrlen)

async def _getpeername(sysif: SyscallInterface, sockfd: near.FileDescriptor,
                       addr: near.Address, addrlen: near.Address) -> None:
    await sysif.syscall(SYS.getpeername, sockfd, addr, addrlen)

async def _getsockopt(sysif: SyscallInterface, sockfd: near.FileDescriptor,
                      level: int, optname: int, optval: near.Address, optlen: near.Address) -> None:
    await sysif.syscall(SYS.getsockopt, sockfd, level, optname, optval, optlen)

async def _setsockopt(sysif: SyscallInterface, sockfd: near.FileDescriptor,
                      level: int, optname: int, optval: near.Address, optlen: int) -> None:
    await sysif.syscall(SYS.setsockopt, sockfd, level, optname, optval, optlen)

async def _recv(sysif: SyscallInterface, fd: near.FileDescriptor,
                buf: near.Address, count: int, flags: int) -> int:
    return (await sysif.syscall(SYS.recvfrom, fd, buf, count, flags))

async def _send(sysif: SyscallInterface, fd: near.FileDescriptor,
                buf: near.Address, count: int, flags: int) -> int:
    return (await sysif.syscall(SYS.sendto, fd, buf, count, flags))

async def _recvmsg(sysif: SyscallInterface, fd: near.FileDescriptor,
                   msg: near.Address, flags: int) -> int:
    return (await sysif.syscall(SYS.recvmsg, fd, msg, flags))

async def _sendmsg(sysif: SyscallInterface, fd: near.FileDescriptor,
                   msg: near.Address, flags: int) -> int:
    return (await sysif.syscall(SYS.sendmsg, fd, msg, flags))



#### Tests ####
from unittest import TestCase
class TestSocket(TestCase):
    pass
