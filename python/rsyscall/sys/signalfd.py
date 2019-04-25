import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct

from rsyscall.signal import Signals
from rsyscall.sys.wait import ChildCode
import enum

class SFD(enum.IntFlag):
    NONBLOCK = lib.SFD_NONBLOCK
    CLOEXEC = lib.SFD_CLOEXEC

class SignalfdSiginfo(Struct):
    signo: Signals
    code: ChildCode
    pid: int

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct signalfd_siginfo*')
        struct.ssi_signo = self.signo
        struct.ssi_code = self.code
        struct.ssi_pid = self.pid
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='Sigaction')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct signalfd_siginfo const*', ffi.from_buffer(data))
        return cls(
            signo=Signals(struct.ssi_signo),
            code=ChildCode(struct.ssi_code),
            pid=ssi_pid,
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct signalfd_siginfo')
