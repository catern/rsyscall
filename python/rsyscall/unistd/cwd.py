import typing as t

#### Classes ####
from rsyscall.handle.pointer import WrittenPointer
from rsyscall.handle.fd import BaseFileDescriptor, FileDescriptorTask
import os

class CWDTask(FileDescriptorTask):
    async def chdir(self, path: WrittenPointer[t.Union[str, os.PathLike]]) -> None:
        with path.borrow(self) as path_n:
            await _chdir(self.sysif, path_n)

    async def fchdir(self, fd: BaseFileDescriptor) -> None:
        with fd.borrow(self) as fd_n:
            await _fchdir(self.sysif, fd_n)

    async def chroot(self, path: WrittenPointer[t.Union[str, os.PathLike]]) -> None:
        with path.borrow(self) as path_n:
            await _chroot(self.sysif, path_n)

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _chdir(sysif: SyscallInterface, path: near.Address) -> None:
    await sysif.syscall(SYS.chdir, path)

async def _fchdir(sysif: SyscallInterface, fd: near.FileDescriptor) -> None:
    await sysif.syscall(SYS.fchdir, fd)

async def _chroot(sysif: SyscallInterface, path: near.Address) -> None:
    await sysif.syscall(SYS.chroot, path)
