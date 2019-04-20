from __future__ import annotations
import typing as t
from rsyscall._raw import lib # type: ignore
from signal import Signals
import enum

class SA(enum.IntFlag):
    NOCLDSTOP = lib.SA_NOCLDSTOP
    NOCLDWAIT = lib.SA_NOCLDWAIT
    NODEFER = lib.SA_NODEFER
    ONSTACK = lib.SA_ONSTACK
    RESETHAND = lib.SA_RESETHAND
    RESTART = lib.SA_RESTART
    RESTORER = lib.SA_RESTORER
    SIGINFO = lib.SA_SIGINFO

class SigprocmaskHow(enum.IntEnum):
    BLOCK = lib.SIG_BLOCK
    UNBLOCK = lib.SIG_UNBLOCK
    SETMASK = lib.SIG_SETMASK

class Sighandler(enum.IntEnum):
    IGN = lib.SIG_IGN
    DFL = lib.SIG_DFL

class Sigset(Struct, t.Set[Signals]):
    "A fixed-size 64-bit sigset"
    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct sigset_t*', )))

    T = t.TypeVar('T', bound='EpollEvent')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct epoll_event*', ffi.from_buffer(data))
        return cls(struct.data.u64, EpollEventMask(struct.events))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct epoll_event')

@dataclass
class Sigaction(Struct):
    handler: t.Union[Sighandler, FunctionPointer]
    flags: SA
    mask: Sigset
    restorer: t.Optional[FunctionPointer] = None

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct sigaction const*', {
            "sa_handler": int(self.handler),
            "sa_flags": self.flags,
            # TODO hmm I need to convert this into a cffi sigset_t
            "sa_mask": self.mask,
            "sa_sigaction": self.sigaction,
        })))

    T = t.TypeVar('T', bound='EpollEvent')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct epoll_event*', ffi.from_buffer(data))
        return cls(struct.data.u64, EpollEventMask(struct.events))

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct epoll_event')
