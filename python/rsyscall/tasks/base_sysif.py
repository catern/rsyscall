import abc
import contextlib
import math
import trio
from rsyscall.concurrency import SuspendableCoroutine, FIFOFuture
from rsyscall.near.sysif import SyscallInterface, syscall_suspendable
from rsyscall.tasks.connection import Syscall, SyscallConnection
from rsyscall.tasks.util import log_syscall, raise_if_error
from rsyscall.handle import FileDescriptor
from rsyscall.sys.syscall import SYS
from dataclasses import dataclass
import logging
import typing as t

class ConnectionSyscallInterface(SyscallInterface):
    """Shared functionality for definining a syscall interface using SyscallConnection

    """
    def __init__(self, rsyscall_connection: SyscallConnection, logger: logging.Logger) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.logger = logger

    def store_remote_side_handles(self, infd: FileDescriptor, outfd: FileDescriptor) -> None:
        """Store the FD handles that the remote side is using to communicate with us

        We need to track and store these so that we don't close them with garbage
        collection.

        """
        self.infd = infd
        self.outfd = outfd

    def get_activity_fd(self) -> FileDescriptor:
        """Return an fd which is readable when there's other syscalls waiting to be done

        This is true by definition: this fd is read by the rsyscall server to receive
        syscalls, and when this fd is readable, it means there's syscalls to be read.

        """
        return self.infd

    async def close_interface(self) -> None:
        """Close this interface

        We don't immediately close infd and outfd because...  TODO why did we do this.

        """
        await self.rsyscall_connection.close()
        self.infd._invalidate()
        self.outfd._invalidate()

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        syscall = Syscall(
            number, arg1=arg1, arg2=arg2, arg3=arg3, arg4=arg4, arg5=arg5, arg6=arg6)
        try:
            result = await self.rsyscall_connection.do_syscall(syscall)
            raise_if_error(result)
        except OSError as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise OSError(exn.errno, exn.strerror) from None
        except Exception as exn:
            self.logger.debug("%s -/ %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result
