from rsyscall.base import Pointer, RsyscallException, RsyscallHangup
from rsyscall.base import T_addr, UnixAddress, PathTooLongError, InetAddress
import rsyscall.raw_syscalls as raw_syscall
import rsyscall.memory as memory
import rsyscall.far as far
import os

# This is like a far pointer plus a segment register.
# I'll call it a... able pointer.
# Or a reachable pointer?
# Or a mapped pointer?
# Or a plotted pointer?
@dataclass
class FileDescriptor:
    task: far.Task
    far: far.FileDescriptor

    def __str__(self) -> str:
        return f"FD({self.task}, {self.far.fd_table}, {self.far.near.number})"

    async def read(self, buf: far.Pointer, count: int) -> int:
        return (await far.read(self.task, self.far, buf, count))

    async def write(self, buf: far.Pointer, count: int) -> int:
        return (await far.write(self.task, self.far, buf, count))
