from __future__ import annotations
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.ctypes import Pointer
from rsyscall.struct import Struct, bits
from dataclasses import dataclass, field
import enum

import signal

# re-exported
from signal import Signals

class SA(enum.IntFlag):
    NOCLDSTOP = lib.SA_NOCLDSTOP
    NOCLDWAIT = lib.SA_NOCLDWAIT
    NODEFER = lib.SA_NODEFER
    ONSTACK = lib.SA_ONSTACK
    RESETHAND = lib.SA_RESETHAND
    RESTART = lib.SA_RESTART
    SIGINFO = lib.SA_SIGINFO
    RESTORER = lib.SA_RESTORER

class SigprocmaskHow(enum.IntEnum):
    BLOCK = lib.SIG_BLOCK
    UNBLOCK = lib.SIG_UNBLOCK
    SETMASK = lib.SIG_SETMASK

class Sighandler(enum.IntEnum):
    IGN = signal.Handlers.SIG_IGN
    DFL = signal.Handlers.SIG_DFL

@dataclass
class Siginfo(Struct):
    code: int
    pid: int
    uid: int
    status: int

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct siginfo*')
        struct.si_code = self.code
        struct.si_pid = self.pid
        struct.si_uid = self.uid
        struct.si_status = self.status
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='Siginfo')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct siginfo const*', ffi.from_buffer(data))
        return cls(
            code=struct.si_code,
            pid=struct.si_pid,
            uid=struct.si_uid,
            status=struct.si_status,
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct siginfo')

class Sigset(t.Set[Signals], Struct):
    "A fixed-size 64-bit sigset"
    def to_cffi(self) -> t.Any:
        set_integer = 0
        for sig in self:
            set_integer |= 1 << (sig-1)
        return ffi.new('struct kernel_sigset*', (set_integer,))

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(self.to_cffi()))

    T = t.TypeVar('T', bound='Sigset')
    @classmethod
    def from_cffi(cls: t.Type[T], struct: t.Any) -> T:
        return cls({Signals(bit) for bit in bits(struct.val)})

    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct kernel_sigset*', ffi.from_buffer(data))
        return cls.from_cffi(struct)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct kernel_sigset')

@dataclass
class Sigaction(Struct):
    handler: t.Union[Sighandler, Pointer]
    flags: SA = SA(0)
    mask: Sigset = field(default_factory=Sigset)
    restorer: t.Optional[Pointer] = None

    def to_bytes(self) -> bytes:
        return bytes(ffi.buffer(ffi.new('struct kernel_sigaction const*', {
            "ksa_handler": ffi.cast('sighandler_t', int(self.handler)),
            "ksa_flags": self.flags,
            "ksa_restorer": ffi.cast('sigrestore_t', int(self.restorer or 0)),
            "ksa_mask": self.mask.to_cffi()[0],
        })))

    T = t.TypeVar('T', bound='Sigaction')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct kernel_sigaction const*', ffi.from_buffer(data))
        handler: t.Union[Sighandler, Pointer]
        int_handler = int(ffi.cast('long int', struct.ksa_handler))
        try:
            handler = Sighandler(int_handler)
        except ValueError:
            handler = Pointer(int_handler)
        int_restorer = int(ffi.cast('long int', struct.ksa_restorer))
        return cls(
            handler=handler,
            flags=SA(struct.ksa_flags),
            mask=Sigset.from_cffi(struct.ksa_mask),
            restorer=Pointer(int_restorer) if int_restorer else None,
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct kernel_sigaction')


#### Tests ####
from unittest import TestCase

class TestSignal(TestCase):
    def test_siginfo(self) -> None:
        initial = Siginfo(13, 581, 1092, 12309)
        output = Siginfo.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)

    def test_sigaction(self) -> None:
        sa = Sigaction(Sighandler.IGN, SA(0), Sigset(), Pointer(0x42))
        out_sa = Sigaction.from_bytes(sa.to_bytes())
        self.assertEqual(sa.handler, out_sa.handler)
        self.assertEqual(sa.flags, out_sa.flags)
        self.assertEqual(sa.mask, out_sa.mask)
        self.assertEqual(sa.restorer, out_sa.restorer)

        sa = Sigaction(Sighandler.DFL, SA.RESTART|SA.RESETHAND,
                       Sigset({Signals.SIGINT, Signals.SIGTERM}),
                       Pointer(0))
        out_sa = Sigaction.from_bytes(sa.to_bytes())
        self.assertEqual(sa.handler, out_sa.handler)
        self.assertEqual(sa.flags, out_sa.flags)
        self.assertEqual(sa.mask, out_sa.mask)
        self.assertEqual(None, out_sa.restorer)
