"""The lowest-level interface for making syscalls

The SyscallInterface is the segment register override prefix, which is used with the
instruction to say which segment register to use for the syscall.

In terms of this metaphor: We don't know from a segment register override prefix alone
that the near pointers we are passing to an instruction are valid pointers in the segment
currently contained in the segment register.

Translating that into concrete terms: We don't know from a SyscallInterface alone that the
identifiers we are passing to a syscall match the namespaces active in the task behind the
SyscallInterface.

(The task is like the segment register, in this analogy.)

"""
from __future__ import annotations
from dataclasses import dataclass
from rsyscall.sys.syscall import SYS
import abc
import typing as t
import os
if t.TYPE_CHECKING:
    import rsyscall.handle as handle

__all__ = [
    "SyscallInterface",
    "SyscallHangup",
]

class SyscallInterface:
    """The lowest-level interface for an object which lets us send syscalls to some process.

    We send syscalls to a process, but nothing in this interface tells us anything about
    the process to which we're sending syscalls; that information is maintained in the
    Task, which contains an object matching this interface.

    This is like the segment register override prefix, with no awareness of the contents
    of the register.

    """
    @abc.abstractmethod
    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        """Send a syscall and wait for it to complete, throwing on error results.

        We provide a guarantee that if the syscall was sent to the process, then we will
        not return until the syscall has completed or our connection has broken.  To
        achieve this, we shield against Python coroutine cancellation while waiting for
        the syscall response.

        This guarantee is important so that our caller can deal with state changes caused
        by the syscall. If our coroutine was cancelled in the middle of a syscall, the
        result of the syscall would be discarded, and our caller wouldn't be able to
        guarantee that state changes in the process are reflected in state changes in
        Python.

        For example, a coroutine calling waitid could be cancelled; if that happened, we
        could discard a child state change indicating that the child exited. If that
        happened, future calls to waitid on that child would be invalid, or maybe return
        events for an unrelated child. We'd be completely confused.

        Instead, thanks to our guarantee, syscalls made through this method can be treated
        as atomic: They will either be submitted and completed, or not submitted at all.
        (If they're submitted and not completed due to blocking forever, that just means
        we'll never return.) There's no possibility of making a syscall, causing a
        side-effect, and never learning about the side-effect you caused.

        Since most syscalls use this method, this guarantee applies to most syscalls.

        This prevents us from cancelling an in-progress syscall if it has already been
        submitted to the process; meaning, we can't discard the result of the syscall, we
        have to wait for it.

        This may seem excessive, but the question is, what should we assume as our default?
        That syscall results can be dropped safely, or that they cannot be dropped?
        Most syscalls are side-effectful: even a simple read usually consumes data in a
        side-effectful matter, and others allocate resources which might be leaked, or can
        cause state changes. Thus, "weakening" (droppability) is not generally true for
        syscall results: syscall results cannot, in most cases, be safely ignored.

        For callers who want to preserve the ability for their coroutine to be cancelled
        even while waiting for a syscall response, the `submit_syscall` API can be used.

        Note that this Python-level cancellation protection has nothing to do with
        actually interrupting a syscall. That ability is still preserved with this
        interface; just send a signal to trigger an EINTR in the syscalling process, and
        we'll get back that EINTR as the syscall response. If you just want to be able to
        cancel deadlocked processes, you should do that. That's the true API for
        "cancellation" of syscalls on Linux.

        Likewise, if the rsyscall server dies, or we get an EOF on the syscall connection,
        or any other event causes response.receive to throw an exception, we'll still
        return that exception; so you can always fall back on killing the rsyscall server
        to stop a deadlock.

        """
        pass

    # non-syscall operations which we haven't figured out how to get rid of yet
    @abc.abstractmethod
    async def close_interface(self) -> None:
        "Close this syscall interface, shutting down the connection to the remote process."
        pass

    @abc.abstractmethod
    def get_activity_fd(self) -> t.Optional[handle.FileDescriptor]:
        """When this file descriptor is readable, it means other things want to run on this thread.

        Users of the SyscallInterface should ensure that when they block, they are
        monitoring this fd as well.

        Typically, this is the file descriptor which the rsyscall server reads for
        incoming syscalls.

        """
        pass

@dataclass
class Syscall:
    number: SYS
    arg1: t.SupportsInt
    arg2: t.SupportsInt
    arg3: t.SupportsInt
    arg4: t.SupportsInt
    arg5: t.SupportsInt
    arg6: t.SupportsInt

    def __str__(self) -> str:
        args = [self.arg1, self.arg2, self.arg3, self.arg4, self.arg5, self.arg6]
        while args and args[-1] == 0:
            args.pop()
        return f"{self.number}({','.join(map(str, args))})"

    def __repr__(self) -> str:
        return str(self)

class SyscallError(Exception):
    """Something prevents us from returning a normal result for this syscall.

    The syscall may or may not have been actually sent to the process,
    and may or may not have actually been executed.

    This is a permanent error; all future syscalls on this interface
    will also fail with a SyscallError.

    Raised by SyscallInterface.syscall.

    """
    pass

class SyscallHangup(SyscallError):
    """This syscall was sent, but we got the equivalent of a hangup when we read the result.

    We don't know if the syscall was actually executed or not.  The
    hangup may not be actually related to the syscall we sent; we'd
    also get a hangup for syscalls if the process died.

    Note that for some syscalls (exit and exec, namely), this result
    indicates success. (Although not with absolute certainty, since
    the hangup could also be unrelated in those cases.)

    Raised by SyscallInterface.syscall.

    """
    pass

class SyscallSendError(SyscallError):
    """We encountered an error when we tried to send this syscall.

    We know for sure that this syscall was not sent and was not
    executed.

    Raised by SyscallInterface.syscall.
    """
    pass

def raise_if_error(response: int) -> None:
    "Raise an OSError if this integer is in the error range for syscall return values"
    if -4095 < response < 0:
        err = -response
        raise OSError(err, os.strerror(err))

class UnusableSyscallInterface(SyscallInterface):
    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        raise SyscallSendError("can't send syscalls through this sysif")

    async def close_interface(self) -> None:
        pass

    def get_activity_fd(self) -> t.Optional[handle.FileDescriptor]:
        raise Exception("can't get an activity fd from this sysif")
