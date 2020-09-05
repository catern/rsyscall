import typing as t
import trio

#### Raw syscalls ####
import rsyscall.near.types as near
from rsyscall.near.sysif import SyscallInterface, SyscallHangup
from rsyscall.sys.syscall import SYS

async def _execve(sysif: SyscallInterface,
                  path: near.Address, argv: near.Address, envp: near.Address) -> None:
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execve, path, argv, envp)

async def _execveat(sysif: SyscallInterface,
                    dirfd: t.Optional[near.FileDescriptor], path: near.Address,
                    argv: near.Address, envp: near.Address, flags: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execveat, dirfd, path, argv, envp, flags)

async def _exit(sysif: SyscallInterface, status: int) -> None:
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.exit, status)
