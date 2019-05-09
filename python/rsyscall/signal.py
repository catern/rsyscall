from __future__ import annotations
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct, bits
from dataclasses import dataclass, field
import enum
import contextlib
from rsyscall.ctypes import Pointer as CPointer
if t.TYPE_CHECKING:
    from rsyscall.far import Task
    from rsyscall.handle import Pointer, WrittenPointer
else:
    Task = object

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

class MaskSIG(enum.IntEnum):
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
    handler: t.Union[Sighandler, CPointer]
    flags: SA = SA(0)
    mask: Sigset = field(default_factory=Sigset)
    restorer: t.Optional[CPointer] = None

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
        handler: t.Union[Sighandler, CPointer]
        int_handler = int(ffi.cast('long int', struct.ksa_handler))
        try:
            handler = Sighandler(int_handler)
        except ValueError:
            handler = CPointer(int_handler)
        int_restorer = int(ffi.cast('long int', struct.ksa_restorer))
        return cls(
            handler=handler,
            flags=SA(struct.ksa_flags),
            mask=Sigset.from_cffi(struct.ksa_mask),
            restorer=CPointer(int_restorer) if int_restorer else None,
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct kernel_sigaction')



#### Signal blocking

class SignalMaskTask(Task):
    def __post_init__(self) -> None:
        super().__post_init__()
        self.sigmask = Sigset()
        self.old_sigmask = Sigset()
        self.sigmask_oldset_ptr: t.Optional[Pointer[Sigset]] = None
        self.sigprocmask_running = False

    @t.overload
    async def sigprocmask(self, newset: t.Tuple[MaskSIG, WrittenPointer[Sigset]]) -> None: ...
    @t.overload
    async def sigprocmask(self, newset: t.Optional[t.Tuple[MaskSIG, WrittenPointer[Sigset]]],
                          oldset: Pointer[Sigset]) -> Pointer[Sigset]: ...

    async def sigprocmask(self, newset: t.Optional[t.Tuple[MaskSIG, WrittenPointer[Sigset]]],
                          oldset: t.Optional[Pointer[Sigset]]=None) -> t.Optional[Pointer[Sigset]]:
        if self.sigprocmask_running:
            # this isn't really true. we know exactly the result of multiple sigprocmask calls,
            # as long as we know which one happened last.
            # with waitid, we don't know what the result of the previous call will be,
            # so it's not safe to call again.
            # but with sigprocmask, we're idempotent.
            # TODO we can loosen this if we can determine the real order that syscalls are made,
            # even through the pipelining.
            raise Exception("sigprocmask is currently being called, "
                            "we disallow multiple simultaneous calls for implementation simplicity")
        self.sigprocmask_running = True
        if newset is None:
            ret = await self._sigprocmask(None, oldset)
            self.sigprocmask_running = False
            return ret
        else:
            how, set = newset
            if how == MaskSIG.BLOCK:
                new_sigmask = Sigset(self.sigmask.union(set.value))
            elif how == MaskSIG.UNBLOCK:
                new_sigmask = Sigset(self.sigmask - set.value)
            elif how == MaskSIG.SETMASK:
                new_sigmask = Sigset(set.value)
            ret = await self._sigprocmask(newset, oldset)
            self.sigprocmask_running = False
            if oldset is not None:
                self.old_sigmask = self.sigmask
                self.sigmask_oldset_ptr = oldset
            self.sigmask = new_sigmask
            return ret

    async def sigmask_block(self, newset: WrittenPointer[Sigset], oldset: t.Optional[Pointer[Sigset]]=None) -> SignalBlock:
        if len(newset.value.intersection(self.sigmask)) != 0:
            raise Exception("can't allocate a SignalBlock for a signal that was already blocked",
                            newset.value, self.sigmask)
        if oldset:
            await self.sigprocmask((MaskSIG.BLOCK, newset), oldset)
        else:
            await self.sigprocmask((MaskSIG.BLOCK, newset))
        return SignalBlock(self, newset)

    async def _sigprocmask(self, newset: t.Optional[t.Tuple[MaskSIG, WrittenPointer[Sigset]]],
                          oldset: t.Optional[Pointer[Sigset]]=None) -> t.Optional[Pointer[Sigset]]:
        import rsyscall.near
        with contextlib.ExitStack() as stack:
            newset_n: t.Optional[t.Tuple[MaskSIG, rsyscall.near.Pointer]]
            if newset:
                stack.enter_context(newset[1].borrow(self))
                newset_n = newset[0], newset[1].near
            else:
                newset_n = None
            oldset_n = await self._borrow_optional(stack, oldset)
            await rsyscall.near.rt_sigprocmask(self.sysif, newset_n, oldset_n, Sigset.sizeof())
        if oldset:
            return oldset
        else:
            return None

    async def read_oldset_and_check(self) -> None:
        if self.sigmask_oldset_ptr is None:
            raise Exception("can't check our tracking of sigmask "
                            "when we haven't called sigprocmask with an oldset ptr")
        sigmask = await self.sigmask_oldset_ptr.read()
        if sigmask != self.old_sigmask:
            raise Exception("SignalMask tracking got out of sync, thought mask was",
                            self.old_sigmask, "but was actually", sigmask)

@dataclass(eq=False)
class SignalBlock:
    """This represents some signals being blocked from normal handling

    We need this around to use alternative signal handling mechanisms
    such as signalfd.

    """
    task: SignalMaskTask
    newset: WrittenPointer[Sigset]

    @property
    def mask(self) -> Sigset:
        return self.newset.value

    async def unblock(self, oldset: t.Optional[Pointer[Sigset]]=None) -> None:
        if oldset:
            await self.task.sigprocmask((MaskSIG.UNBLOCK, self.newset), oldset)
        else:
            await self.task.sigprocmask((MaskSIG.UNBLOCK, self.newset))


#### Tests ####
from unittest import TestCase

class TestSignal(TestCase):
    def test_siginfo(self) -> None:
        initial = Siginfo(13, 581, 1092, 12309)
        output = Siginfo.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)

    def test_sigaction(self) -> None:
        sa = Sigaction(Sighandler.IGN, SA(0), Sigset(), CPointer(0x42))
        out_sa = Sigaction.from_bytes(sa.to_bytes())
        self.assertEqual(sa.handler, out_sa.handler)
        self.assertEqual(sa.flags, out_sa.flags)
        self.assertEqual(sa.mask, out_sa.mask)
        self.assertEqual(sa.restorer, out_sa.restorer)

        sa = Sigaction(Sighandler.DFL, SA.RESTART|SA.RESETHAND,
                       Sigset({Signals.SIGINT, Signals.SIGTERM}),
                       CPointer(0))
        out_sa = Sigaction.from_bytes(sa.to_bytes())
        self.assertEqual(sa.handler, out_sa.handler)
        self.assertEqual(sa.flags, out_sa.flags)
        self.assertEqual(sa.mask, out_sa.mask)
        self.assertEqual(None, out_sa.restorer)
