"""`#include <sys/capability.h>`

See capget(2).

"""
from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.struct import Struct, bits
from dataclasses import dataclass
import typing as t
import enum

__all__ = [
    "CAP",
    "CapHeader",
    "CapData",
]

class CAP(enum.IntEnum):
    CHOWN = lib.CAP_CHOWN
    DAC_OVERRIDE = lib.CAP_DAC_OVERRIDE
    DAC_READ_SEARCH = lib.CAP_DAC_READ_SEARCH
    FOWNER = lib.CAP_FOWNER
    FSETID = lib.CAP_FSETID
    KILL = lib.CAP_KILL
    SETGID = lib.CAP_SETGID
    SETUID = lib.CAP_SETUID
    SETPCAP = lib.CAP_SETPCAP
    LINUX_IMMUTABLE = lib.CAP_LINUX_IMMUTABLE
    NET_BIND_SERVICE = lib.CAP_NET_BIND_SERVICE
    NET_BROADCAST = lib.CAP_NET_BROADCAST
    NET_ADMIN = lib.CAP_NET_ADMIN
    NET_RAW = lib.CAP_NET_RAW
    IPC_LOCK = lib.CAP_IPC_LOCK
    IPC_OWNER = lib.CAP_IPC_OWNER
    SYS_MODULE = lib.CAP_SYS_MODULE
    SYS_RAWIO = lib.CAP_SYS_RAWIO
    SYS_CHROOT = lib.CAP_SYS_CHROOT
    SYS_PTRACE = lib.CAP_SYS_PTRACE
    SYS_PACCT = lib.CAP_SYS_PACCT
    SYS_ADMIN = lib.CAP_SYS_ADMIN
    SYS_BOOT = lib.CAP_SYS_BOOT
    SYS_NICE = lib.CAP_SYS_NICE
    SYS_RESOURCE = lib.CAP_SYS_RESOURCE
    SYS_TIME = lib.CAP_SYS_TIME
    SYS_TTY_CONFIG = lib.CAP_SYS_TTY_CONFIG
    MKNOD = lib.CAP_MKNOD
    LEASE = lib.CAP_LEASE
    AUDIT_WRITE = lib.CAP_AUDIT_WRITE
    AUDIT_CONTROL = lib.CAP_AUDIT_CONTROL
    SETFCAP = lib.CAP_SETFCAP
    MAC_OVERRIDE = lib.CAP_MAC_OVERRIDE
    MAC_ADMIN = lib.CAP_MAC_ADMIN
    SYSLOG = lib.CAP_SYSLOG
    WAKE_ALARM = lib.CAP_WAKE_ALARM
    BLOCK_SUSPEND = lib.CAP_BLOCK_SUSPEND
    AUDIT_READ = lib.CAP_AUDIT_READ
    PERFMON = lib.CAP_PERFMON
    BPF = lib.CAP_BPF
    CHECKPOINT_RESTORE = lib.CAP_CHECKPOINT_RESTORE

def to_uint32s(caps: t.Set[CAP]) -> t.Tuple[int, int]:
    ret: t.List[int] = [0, 0]
    for cap in caps:
        list_idx = (cap // 32)
        uint_idx = (cap % 32)
        ret[list_idx] |= 1 << uint_idx
    return tuple(ret) # type: ignore

def from_uint32s(one: int, two: int) -> t.Set[CAP]:
    return {*{CAP(bit) for bit in bits(one, one_indexed=False)},
            *{CAP(bit+32) for bit in bits(two, one_indexed=False)}}

@dataclass
class CapHeader(Struct):
    # if 0, defaults to calling thread; note that this is a task id, not a thread group id.
    pid: int = 0

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct __user_cap_header_struct*', (lib._LINUX_CAPABILITY_VERSION_3, self.pid))
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='CapHeader')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct __user_cap_header_struct*', ffi.from_buffer(data))
        return cls(struct.pid)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct __user_cap_header_struct')

@dataclass
class CapData(Struct):
    "struct __user_cap_data_struct, version 3"
    effective: t.Set[CAP]
    permitted: t.Set[CAP]
    inheritable: t.Set[CAP]

    def to_bytes(self) -> bytes:
        struct = ffi.new('struct __user_cap_data_struct[2]')
        capset_names = ['effective', 'permitted', 'inheritable']
        for name in capset_names:
            capset = getattr(self, name)
            one, two = to_uint32s(capset)
            setattr(struct[0], name, one)
            setattr(struct[1], name, two)
        return bytes(ffi.buffer(struct))

    T = t.TypeVar('T', bound='CapData')
    @classmethod
    def from_bytes(cls: t.Type[T], data: bytes) -> T:
        struct = ffi.cast('struct __user_cap_data_struct[2]', ffi.from_buffer(data))
        capset_names = ['effective', 'permitted', 'inheritable']
        capsets: t.List[t.Set[CAP]] = []
        for name in capset_names:
            one, two = getattr(struct[0], name), getattr(struct[1], name)
            capset = from_uint32s(one, two)
            capsets.append(capset)
        return cls(*capsets)

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct __user_cap_data_struct[2]')

#### Classes ####
from rsyscall.handle.pointer import Pointer, WrittenPointer, ReadablePointer
import rsyscall.far

class CapabilityTask(rsyscall.far.Task):
    async def capset(self, hdrp: WrittenPointer[CapHeader], datap: WrittenPointer[CapData]) -> None:
        with hdrp.borrow(self):
            with datap.borrow(self):
                await _capset(self.sysif, hdrp.near, datap.near)

    async def capget(self, hdrp: WrittenPointer[CapHeader], datap: Pointer[CapData]) -> ReadablePointer[CapData]:
        with hdrp.borrow(self):
            with datap.borrow(self):
                await _capget(self.sysif, hdrp.near, datap.near)
                return datap._readable()

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _capget(sysif: SyscallInterface, hdrp: near.Address, datap: near.Address) -> None:
    await sysif.syscall(SYS.capget, hdrp, datap)

async def _capset(sysif: SyscallInterface, hdrp: near.Address, datap: near.Address) -> None:
    await sysif.syscall(SYS.capset, hdrp, datap)
