from __future__ import annotations
from rsyscall._raw import ffi, lib # type: ignore
from dataclasses import dataclass
from rsyscall.struct import FixedSize, Serializer
import rsyscall.near.types as near
from rsyscall.handle.fd import FileDescriptorTask
import typing as t
if t.TYPE_CHECKING:
    from rsyscall.handle import FileDescriptor

T_pipe = t.TypeVar('T_pipe', bound='Pipe')
@dataclass
class Pipe(FixedSize):
    "A pair of file descriptors, as written by pipe."
    read: FileDescriptor
    write: FileDescriptor

    def __getitem__(self, idx: int) -> FileDescriptor:
        if idx == 0:
            return self.read
        elif idx == 1:
            return self.write
        else:
            raise IndexError("only index 0 or 1 are valid for Pipe:", idx)

    def __iter__(self) -> t.Iterable[FileDescriptor]:
        return iter([self.read, self.write])

    @classmethod
    def sizeof(cls) -> int:
        return ffi.sizeof('struct fdpair')

    @classmethod
    def get_serializer(cls: t.Type[T_pipe], task: FileDescriptorTask[FileDescriptor]) -> Serializer[T_pipe]:
        return PipeSerializer(cls, task)

@dataclass
class PipeSerializer(Serializer[T_pipe]):
    cls: t.Type[T_pipe]
    task: FileDescriptorTask[FileDescriptor]

    def to_bytes(self, pair: T_pipe) -> bytes:
        struct = ffi.new('struct fdpair*', (pair.read, pair.write))
        return bytes(ffi.buffer(struct))

    def from_bytes(self, data: bytes) -> T_pipe:
        struct = ffi.cast('struct fdpair const*', ffi.from_buffer(data))
        def make(n: int) -> FileDescriptor:
            return self.task.make_fd_handle(near.FileDescriptor(int(n)))
        return self.cls(make(struct.first), make(struct.second))

#### Classes ####
from rsyscall.fcntl import O
from rsyscall.handle.pointer import Pointer, LinearPointer

class PipeTask(FileDescriptorTask):
    async def pipe(self, buf: Pointer[Pipe], flags: O=O.NONE) -> LinearPointer[Pipe]:
        """create pipe

        manpage: pipe2(2)
        """
        # TODO we should force the serializer for the pipe to be using this task...
        # otherwise it could get deserialized by a task with which we share memory,
        # but not share file descriptor tables.
        # Maybe we could create the Serializer right here, and discard
        # the passed-in one? That wouldn't allow a different task in
        # the same fd table to receive the handles though.
        with buf.borrow(self):
            await _pipe(self.sysif, buf.near, flags|O.CLOEXEC)
            return buf._linearize()

#### Raw syscalls ####
from rsyscall.near.sysif import SyscallInterface
from rsyscall.sys.syscall import SYS

async def _pipe(sysif: SyscallInterface, pipefd: near.Address, flags: O) -> None:
    await sysif.syscall(SYS.pipe2, pipefd, flags)
