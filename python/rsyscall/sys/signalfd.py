"`#include <sys/signalfd.h>`"
import typing as t
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct
from dataclasses import dataclass

from rsyscall.signal import SIG, Sigset
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

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask
from rsyscall.handle.pointer import Pointer

T_fd = t.TypeVar('T_fd', bound='SignalFileDescriptor')
class SignalFileDescriptor(BaseFileDescriptor):
    async def signalfd(self, mask: Pointer[Sigset], flags: SFD) -> None:
        self._validate()
        with mask.borrow(self.task) as mask_n:
            await _signalfd(self.task.sysif, self.near, mask_n, mask.size(), flags)

class SignalfdTask(FileDescriptorTask[T_fd]):
    async def signalfd(self, mask: Pointer[Sigset], flags: SFD=SFD.NONE) -> T_fd:
        with mask.borrow(self) as mask_n:
            fd = await _signalfd(self.sysif, None, mask_n, mask.size(), flags|SFD.CLOEXEC)
            return self.make_fd_handle(fd)

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _signalfd(sysif: SyscallInterface, fd: t.Optional[near.FileDescriptor],
                    mask: near.Address, sizemask: int, flags: SFD) -> near.FileDescriptor:
    if fd is None:
        fd = -1 # type: ignore
    return near.FileDescriptor(await sysif.syscall(SYS.signalfd4, fd, mask, sizemask, flags))
