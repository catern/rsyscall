"""`#include <sys/ioctl.h>`

Abandon all hope, ye who enter here.

"""
import typing as t
import errno

#### Classes ####
from rsyscall.handle.fd import BaseFileDescriptor
from rsyscall.handle.pointer import Pointer

class IoctlFileDescriptor(BaseFileDescriptor):
    async def ioctl(self, request: int, arg: Pointer) -> int:
        self._validate()
        arg._validate()
        try:
            return (await _ioctl(self.task.sysif, self.near, request, arg.near))
        except OSError as e:
            if e.errno == errno.ENOTTY:
                e.filename = request
            raise

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _ioctl(sysif: SyscallInterface, fd: near.FileDescriptor,
                request: int, arg: t.Optional[t.Union[int, near.Address]]=None) -> int:
    if arg is None:
        arg = 0
    return (await sysif.syscall(SYS.ioctl, fd, request, arg))

