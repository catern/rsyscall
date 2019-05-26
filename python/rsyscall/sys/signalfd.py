import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct
from dataclasses import dataclass

from rsyscall.signal import SIG
import enum

class SFD(enum.IntFlag):
    NONE = 0
    NONBLOCK = lib.SFD_NONBLOCK
    CLOEXEC = lib.SFD_CLOEXEC

@dataclass
class SignalfdSiginfo(Struct):
    # TODO fill in the rest of the data
    # (even though we don't use any of it ourselves)
    signo: SIG

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct signalfd_siginfo*')
        struct.ssi_signo = self.signo
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='SignalfdSiginfo')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct signalfd_siginfo const*', ffi.from_buffer(data))
        return cls(
            signo=SIG(struct.ssi_signo),
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct signalfd_siginfo')
