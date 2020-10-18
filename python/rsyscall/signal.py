"`#include <signal.h>`"
from __future__ import annotations
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct, bits
from dataclasses import dataclass, field
import enum
import contextlib
import rsyscall.near.types as near
from rsyscall.far import Task
from rsyscall.handle import Pointer, WrittenPointer

import signal

__all__ = [
    "SIG",
    "SA",
    "HowSIG",
    "Sighandler",
    "Siginfo",
    "Sigset",
    "Sigaction",
    "SignalBlock",
    "SignalTask",
]

class SIG(enum.IntEnum):
    "All the non-realtime signals, used by many syscalls"
    NONE = 0
    HUP = signal.SIGHUP
    INT = signal.SIGINT
    QUIT = signal.SIGQUIT
    ILL = signal.SIGILL
    TRAP = signal.SIGTRAP
    ABRT = signal.SIGABRT
    IOT = signal.SIGIOT
    BUS = signal.SIGBUS
    FPE = signal.SIGFPE
    KILL = signal.SIGKILL
    USR1 = signal.SIGUSR1
    SEGV = signal.SIGSEGV
    USR2 = signal.SIGUSR2
    PIPE = signal.SIGPIPE
    ALRM = signal.SIGALRM
    TERM = signal.SIGTERM
    STKFLT = lib.SIGSTKFLT
    CHLD = signal.SIGCHLD
    CONT = signal.SIGCONT
    STOP = signal.SIGSTOP
    TSTP = signal.SIGTSTP
    TTIN = signal.SIGTTIN
    TTOU = signal.SIGTTOU
    URG = signal.SIGURG
    XCPU = signal.SIGXCPU
    XFSZ = signal.SIGXFSZ
    VTALRM = signal.SIGVTALRM
    PROF = signal.SIGPROF
    WINCH = signal.SIGWINCH
    IO = signal.SIGIO
    PWR = signal.SIGPWR
    SYS = signal.SIGSYS

class SA(enum.IntFlag):
    "Flags which can be set in a struct sigaction passed to the sigaction syscall"
    NOCLDSTOP = lib.SA_NOCLDSTOP
    NOCLDWAIT = lib.SA_NOCLDWAIT
    NODEFER = lib.SA_NODEFER
    ONSTACK = lib.SA_ONSTACK
    RESETHAND = lib.SA_RESETHAND
    RESTART = lib.SA_RESTART
    SIGINFO = lib.SA_SIGINFO
    RESTORER = lib.SA_RESTORER

class HowSIG(enum.IntEnum):
    "The how argument to sigprocmask"
    BLOCK = lib.SIG_BLOCK
    UNBLOCK = lib.SIG_UNBLOCK
    SETMASK = lib.SIG_SETMASK

class Sighandler(enum.IntEnum):
    "Special-cased signal handler values used by sigaction"
    IGN = signal.Handlers.SIG_IGN
    DFL = signal.Handlers.SIG_DFL

@dataclass
class Siginfo(Struct):
    "struct siginfo, returned by many syscalls"
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

class Sigset(t.Set[SIG], Struct):
    """A fixed-size 64-signal struct sigset

    Technically, at the syscall level, struct sigset is variable size. It was
    made variable size when the number of signals was increased from 32 to 64
    and the "rt" variants of many signal syscalls was added, taking as an
    additional argument the size of struct sigset. But it's unlikely the number
    of signals will ever be increased again on Linux, and even if that does
    happen, it will be backwrds-compatible.

    """
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
        return cls({SIG(bit) for bit in bits(struct.val)})

    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct kernel_sigset*', ffi.from_buffer(data))
        return cls.from_cffi(struct)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct kernel_sigset')

@dataclass
class Sigaction(Struct):
    "struct sigaction, passed to and returned from the sigaction syscall"
    handler: t.Union[Sighandler, near.Address]
    flags: SA = SA(0)
    mask: Sigset = field(default_factory=Sigset)
    restorer: t.Optional[near.Address] = None

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
        handler: t.Union[Sighandler, near.Address]
        int_handler = int(ffi.cast('long int', struct.ksa_handler))
        try:
            handler = Sighandler(int_handler)
        except ValueError:
            handler = near.Address(int_handler)
        int_restorer = int(ffi.cast('long int', struct.ksa_restorer))
        return cls(
            handler=handler,
            flags=SA(struct.ksa_flags),
            mask=Sigset.from_cffi(struct.ksa_mask),
            restorer=near.Address(int_restorer) if int_restorer else None,
        )

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct kernel_sigaction')



#### Classes ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _rt_sigprocmask(sysif: SyscallInterface,
                          newset: t.Optional[t.Tuple[HowSIG, near.Address]],
                          oldset: t.Optional[near.Address],
                          sigsetsize: int) -> None:
    "The raw, near, rt_sigprocmask syscall."
    if newset is not None:
        how, set = newset
    else:
        how, set = 0, 0 # type: ignore
    if oldset is None:
        oldset = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigprocmask, how, set, oldset, sigsetsize)

class SignalTask(Task):
    "The subset of functionality of the Task related to blocking and handling signals"
    def __post_init__(self) -> None:
        super().__post_init__()
        self.sigmask = Sigset()
        self.old_sigmask = Sigset()
        self.sigmask_oldset_ptr: t.Optional[Pointer[Sigset]] = None
        self.sigprocmask_running = False

    async def sigaction(self, signum: SIG,
                        act: t.Optional[Pointer[Sigaction]],
                        oldact: t.Optional[Pointer[Sigaction]]) -> None:
        with contextlib.ExitStack() as stack:
            act_n = self._borrow_optional(stack, act)
            oldact_n = self._borrow_optional(stack, oldact)
            # rt_sigaction takes the size of the sigset, not the size of the sigaction;
            # and sigset is a fixed size.
            await _rt_sigaction(self.sysif, signum, act_n, oldact_n, Sigset.sizeof())

    async def _sigprocmask(self, newset: t.Optional[t.Tuple[HowSIG, WrittenPointer[Sigset]]],
                           oldset: t.Optional[Pointer[Sigset]]=None) -> t.Optional[Pointer[Sigset]]:
        "The low-level implementation of sigprocmask, without any tracking of our current sigmask."
        with contextlib.ExitStack() as stack:
            newset_n: t.Optional[t.Tuple[HowSIG, near.Address]]
            if newset:
                newset_ptr_n = stack.enter_context(newset[1].borrow(self))
                newset_n = newset[0], newset_ptr_n
            else:
                newset_n = None
            oldset_n = self._borrow_optional(stack, oldset)
            await _rt_sigprocmask(self.sysif, newset_n, oldset_n, Sigset.sizeof())
        if oldset:
            return oldset
        else:
            return None

    @t.overload
    async def sigprocmask(self, newset: t.Tuple[HowSIG, WrittenPointer[Sigset]]) -> None: ...
    @t.overload
    async def sigprocmask(self, newset: t.Optional[t.Tuple[HowSIG, WrittenPointer[Sigset]]],
                          oldset: Pointer[Sigset]) -> Pointer[Sigset]: ...

    async def sigprocmask(self, newset: t.Optional[t.Tuple[HowSIG, WrittenPointer[Sigset]]],
                          oldset: t.Optional[Pointer[Sigset]]=None) -> t.Optional[Pointer[Sigset]]:
        "sigprocmask, with additional tracking of what we believe our sigmask is"
        if self.sigprocmask_running:
            # TODO we can remove this restriction if we can determine the real order that
            # syscalls are made, so we can accurately maintain sigmask; that's currently
            # tricky due to pipelining.
            raise Exception("sigprocmask is currently being called, "
                            "we disallow multiple simultaneous calls for implementation simplicity")
        self.sigprocmask_running = True
        if newset is None:
            ret = await self._sigprocmask(None, oldset)
            self.sigprocmask_running = False
            return ret
        else:
            how, set = newset
            if how == HowSIG.BLOCK:
                new_sigmask = Sigset(self.sigmask.union(set.value))
            elif how == HowSIG.UNBLOCK:
                new_sigmask = Sigset(self.sigmask - set.value)
            elif how == HowSIG.SETMASK:
                new_sigmask = Sigset(set.value)
            ret = await self._sigprocmask(newset, oldset)
            self.sigprocmask_running = False
            if oldset is not None:
                self.old_sigmask = self.sigmask
                self.sigmask_oldset_ptr = oldset
            self.sigmask = new_sigmask
            return ret

    async def sigmask_block(self, newset: WrittenPointer[Sigset], oldset: t.Optional[Pointer[Sigset]]=None) -> SignalBlock:
        "Block some signals and get back a SignalBlock to witness and own those blocked signals"
        if len(newset.value.intersection(self.sigmask)) != 0:
            raise Exception("can't allocate a SignalBlock for a signal that was already blocked",
                            newset.value, self.sigmask)
        if oldset:
            await self.sigprocmask((HowSIG.BLOCK, newset), oldset)
        else:
            await self.sigprocmask((HowSIG.BLOCK, newset))
        return SignalBlock(self, newset)

    async def read_oldset_and_check(self) -> None:
        """Read the most recent oldset buffer passed to sigprocmask and check it matches what we expect

        We do this in a separate method to avoid forcing the user to read memory
        if they don't want to validate that the oldset buffer contains what they
        expect. They can call it later if they want to do the check.

        """
        if self.sigmask_oldset_ptr is None:
            raise Exception("can't check our tracking of sigmask "
                            "when we haven't called sigprocmask with an oldset ptr")
        sigmask = await self.sigmask_oldset_ptr.read()
        if (sigmask & self.old_sigmask) != self.old_sigmask:
            raise Exception("SignalMask tracking got out of sync, we blocked these signals:", self.old_sigmask,
                            "but the actually blocked signals don't include all of those:", sigmask)

@dataclass(eq=False)
class SignalBlock:
    """This represents some signals being blocked from normal handling

    We need this around to use alternative signal handling mechanisms
    such as signalfd.

    This serves as both a witness that we have indeed blocked these signals, and
    an owner to help us unblock those signals if and when we no longer need to
    block them.

    """
    task: SignalTask
    newset: WrittenPointer[Sigset]

    @property
    def mask(self) -> Sigset:
        return self.newset.value

    async def unblock(self, oldset: t.Optional[Pointer[Sigset]]=None) -> None:
        if oldset:
            await self.task.sigprocmask((HowSIG.UNBLOCK, self.newset), oldset)
        else:
            await self.task.sigprocmask((HowSIG.UNBLOCK, self.newset))


#### Raw syscalls ####
async def _rt_sigaction(sysif: SyscallInterface, signum: SIG,
                        act: t.Optional[near.Address],
                        oldact: t.Optional[near.Address],
                        size: int) -> None:
    if act is None:
        act = 0 # type: ignore
    if oldact is None:
        oldact = 0 # type: ignore
    await sysif.syscall(SYS.rt_sigaction, signum, act, oldact, size)

async def _kill(sysif: SyscallInterface, pid: t.Union[near.Process, near.ProcessGroup], sig: SIG) -> None:
    if isinstance(pid, near.ProcessGroup):
        pid = -int(pid) # type: ignore
    await sysif.syscall(SYS.kill, pid, sig)


#### Tests ####
from unittest import TestCase

class TestSignal(TestCase):
    def test_siginfo(self) -> None:
        initial = Siginfo(13, 581, 1092, 12309)
        output = Siginfo.from_bytes(initial.to_bytes())
        self.assertEqual(initial, output)

    def test_sigaction(self) -> None:
        sa = Sigaction(Sighandler.IGN, SA(0), Sigset(), near.Address(0x42))
        out_sa = Sigaction.from_bytes(sa.to_bytes())
        self.assertEqual(sa.handler, out_sa.handler)
        self.assertEqual(sa.flags, out_sa.flags)
        self.assertEqual(sa.mask, out_sa.mask)
        self.assertEqual(sa.restorer, out_sa.restorer)

        sa = Sigaction(Sighandler.DFL, SA.RESTART|SA.RESETHAND,
                       Sigset({SIG.INT, SIG.TERM}),
                       near.Address(0))
        out_sa = Sigaction.from_bytes(sa.to_bytes())
        self.assertEqual(sa.handler, out_sa.handler)
        self.assertEqual(sa.flags, out_sa.flags)
        self.assertEqual(sa.mask, out_sa.mask)
        self.assertEqual(None, out_sa.restorer)
