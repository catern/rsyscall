from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
import os
import typing as t
import enum

class MFD(enum.IntFlag):
    NONE = 0
    CLOEXEC = lib.MFD_CLOEXEC
    ALLOW_SEALING = lib.MFD_ALLOW_SEALING
    HUGETLB = lib.MFD_HUGETLB
    HUGE_2MB = lib.MFD_HUGE_2MB
    HUGE_1GB = lib.MFD_HUGE_1GB
    
#### Classes ####
from rsyscall.handle.fd import T_fd, FileDescriptorTask
if t.TYPE_CHECKING:
    from rsyscall.handle.pointer import WrittenPointer

class MemfdTask(FileDescriptorTask[T_fd]):
    async def memfd_create(self, name: WrittenPointer[t.Union[str, os.PathLike]], flags: MFD=MFD.NONE) -> T_fd:
        with name.borrow(self) as name_n:
            fd = await _memfd_create(self.sysif, name_n, flags|MFD.CLOEXEC)
            return self.make_fd_handle(fd)

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _memfd_create(sysif: SyscallInterface,
                        name: near.Address, flags: MFD) -> near.FileDescriptor:
    return near.FileDescriptor(await sysif.syscall(SYS.memfd_create, name, flags))
