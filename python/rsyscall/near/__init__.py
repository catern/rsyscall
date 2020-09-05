"""Definitions of namespace-local identifiers, syscalls, and SyscallInterface

These namespace-local identifiers are like near pointers, in systems
with segmented memory. They are valid only within a specific segment
(namespace).

The syscalls are instructions, operating on near pointers and other
arguments.

The SyscallInterface is the segment register override prefix, which is
used with the instruction to say which segment register to use for the
syscall.

We don't know from a segment register override prefix alone that the
near pointers we are passing to an instruction are valid pointers in
the segment currently contained in the segment register.

In terms of our actual classes: We don't know from a SyscallInterface
alone that the identifiers we are passing to a syscall match the
namespaces active in the task behind the SyscallInterface.

(The task is like the segment register, in this analogy.)

"""

from __future__ import annotations
import trio
import typing as t

# re-exported namepsace-local identifiers
from rsyscall.near.types import (
    FileDescriptor,
    WatchDescriptor,
    Address,
    MemoryMapping,
    Process,
    ProcessGroup,
)
# re-exported SyscallInterface
from rsyscall.near.sysif import SyscallInterface, SyscallResponse, SyscallHangup

from rsyscall.sys.syscall import SYS


#### Syscalls (instructions)
# These are like instructions, run with this segment register override prefix and arguments.
import trio

async def close(sysif: SyscallInterface, fd: FileDescriptor) -> None:
    try:
        await sysif.syscall(SYS.close, fd)
    except OSError as e:
        e.filename = fd
        raise

async def dup3(sysif: SyscallInterface, oldfd: FileDescriptor, newfd: FileDescriptor, flags: int) -> None:
    await sysif.syscall(SYS.dup3, oldfd, newfd, flags)

async def execve(sysif: SyscallInterface,
                 path: Address, argv: Address, envp: Address) -> None:
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execve, path, argv, envp)

async def execveat(sysif: SyscallInterface,
                   dirfd: t.Optional[FileDescriptor], path: Address,
                   argv: Address, envp: Address, flags: int) -> None:
    if dirfd is None:
        dirfd = AT.FDCWD # type: ignore
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.execveat, dirfd, path, argv, envp, flags)

async def exit(sysif: SyscallInterface, status: int) -> None:
    def handle(exn):
        if isinstance(exn, SyscallHangup):
            return None
        else:
            return exn
    with trio.MultiError.catch(handle):
        await sysif.syscall(SYS.exit, status)

async def set_robust_list(sysif: SyscallInterface, head: Address, len: int) -> None:
    await sysif.syscall(SYS.set_robust_list, head, len)

async def set_tid_address(sysif: SyscallInterface, ptr: Address) -> None:
    await sysif.syscall(SYS.set_tid_address, ptr)

async def setns(sysif: SyscallInterface, fd: FileDescriptor, nstype: int) -> None:
    await sysif.syscall(SYS.setns, fd, nstype)

