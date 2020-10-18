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
from rsyscall.near.sysif import SyscallInterface, SyscallHangup
__all__ = [
    'FileDescriptor',
    'WatchDescriptor',
    'Address',
    'MemoryMapping',
    'Process',
    'ProcessGroup',
    'SyscallInterface', 'SyscallHangup',
]
