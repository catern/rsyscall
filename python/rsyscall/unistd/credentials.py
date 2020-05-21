"Named for the excellent manpage about these process attributes, credentials(7)"
from __future__ import annotations
import rsyscall.near as near
import typing as t

#### Classes ####
if t.TYPE_CHECKING:
    from rsyscall.handle.process import ChildProcess
import rsyscall.far

class CredentialsTask(rsyscall.far.Task):
    async def getuid(self) -> int:
        return (await _getuid(self.sysif))

    async def getgid(self) -> int:
        return (await _getgid(self.sysif))

    async def getpid(self) -> near.Process:
        return (await _getpid(self.sysif))

    async def getpgid(self) -> near.ProcessGroup:
        return (await _getpgid(self.sysif, None))

    async def setpgid(self, pgid: t.Optional[ChildProcess]=None) -> None:
        if pgid is None:
            await _setpgid(self.sysif, None, None)
        else:
            if pgid.task.pidns != self.pidns:
                raise rsyscall.far.NamespaceMismatchError(
                    "different pid namespaces", pgid.task.pidns, self.pidns)
            with pgid.borrow():
                await _setpgid(self.sysif, None, pgid._as_process_group())

    async def setsid(self) -> int:
        return (await _setsid(self.sysif))

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _getuid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getuid))

async def _getgid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.getgid))

async def _getpid(sysif: SyscallInterface) -> near.Process:
    return near.Process(await sysif.syscall(SYS.getpid))

async def _getpgid(sysif: SyscallInterface, pid: t.Optional[near.Process]) -> near.ProcessGroup:
    if pid is None:
        pid = 0 # type: ignore
    return near.ProcessGroup(await sysif.syscall(SYS.getpgid, pid))

async def _setpgid(sysif: SyscallInterface,
                   pid: t.Optional[near.Process], pgid: t.Optional[near.ProcessGroup]) -> None:
    if pid is None:
        pid = 0 # type: ignore
    if pgid is None:
        pgid = 0 # type: ignore
    await sysif.syscall(SYS.setpgid, pid, pgid)

async def _setsid(sysif: SyscallInterface) -> int:
    return (await sysif.syscall(SYS.setsid))
