from dataclasses import dataclass

# Here we have base dataclasses which don't carry around references to a task.
# In particular, Pointer, FileDescriptor, and Path all should be in here,
# without a reference to a task.

# The ones in io.py carry a reference to a Task, and so are more convenient for users.

class SyscallInterface:
    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int: ...
    # non-syscall operations which we haven't figured out how to get rid of yet
    async def close_interface(self) -> None: ...
    async def wait_readable(self, fd: int) -> None: ...
    
class AddressSpace:
    def null(self) -> Pointer:
        return Pointer(self, 0)

@dataclass
class Pointer:
    address_space: AddressSpace
    address: int

    def __add__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.address + other)

    def __sub__(self, other: int) -> 'Pointer':
        return Pointer(self.address_space, self.address - other)

class FDNamespace:
    def null(self) -> FileDescriptor:
        return FileDescriptor(self, -1)

@dataclass
class FileDescriptor:
    fd_namespace: FDNamespace
    number: int

class MountNamespace:
    pass

class FSInformation:
    "Filesystem root, current working directory, and umask; controlled by CLONE_FS."
    pass

class Task:
    def __init__(self, pid: int,
                 sysif: SyscallInterface,
                 fd_namespace: FDNamespace,
                 address_space: AddressSpace,
                 mount: MountNamespace,
                 fs: FSInformation,
    ) -> None:
        self.pid = pid
        self.sysif = sysif
        self.fd_namespace = fd_namespace
        self.address_space = address_space
        self.mount = mount
        self.fs = fs
