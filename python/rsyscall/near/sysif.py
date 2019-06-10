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
import logging
import trio
import abc
from rsyscall.sys.syscall import SYS
import typing as t
if t.TYPE_CHECKING:
    import rsyscall.handle as handle

__all__ = [
    "SyscallInterface",
    "SyscallResponse",
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

        For callers who want to preserve the ability for their coroutine to be cancelled
        even while waiting for a syscall response, the `submit_syscall` API can be used.

        Note that this Python-level cancellation protection has nothing to do with
        actually cancelling a syscall. That ability is still preserved with this
        interface; just send a signal to trigger an EINTR in the syscalling process, and
        we'll get back that EINTR as the syscall response. If you just want to be able to
        cancel deadlocked processes, you should do that.

        Likewise, if the rsyscall server dies, or we get an EOF on the syscall connection,
        or any other event causes response.receive to throw an exception, we'll still
        return that exception; so you can always fall back on killing the rsyscall server
        to stop a deadlock.

        """
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            with trio.CancelScope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result

    @abc.abstractmethod
    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        """Submit a syscall without immediately waiting for its response to come back.

        By calling `receive` on SyscallResponse, the caller can wait for the response.

        The primary purpose of this interface is to allow for cancellation. The `syscall`
        method doesn't allow cancellation while waiting for a syscall response. This
        method doesn't wait for the syscall response, and so can be used in scenarios
        where we want to avoid blocking for unneeded syscall responses.

        This interface is not for parallelization or concurrency. The `syscall` method can
        already be called concurrently from multiple coroutines; using this method does
        not give any improved performance characteristics compared to just spinning up
        multiple coroutines to call `syscall` in parallel.

        While this interface does allow the user to avoid blocking for the syscall
        response, using that as an optimization is obviously a bad idea. For correctness,
        you must eventually block for the syscall response to make sure the syscall
        succeeded. Appropriate usage of coroutines allows continuing operation without
        waiting for the syscall response even with `syscall`, while still enforcing that
        eventually we will examine the response.

        """
        pass

    # non-syscall operations which we haven't figured out how to get rid of yet
    logger: logging.Logger

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

class SyscallResponse:
    "A representation of the pending response to some syscall submitted through `submit_syscall`."
    @abc.abstractmethod
    async def receive(self) -> int:
        "Wait for the corresponding syscall to complete and return its result, throwing on error results."
        pass

class SyscallHangup(Exception):
    """The task we were sending syscalls to, has changed state in a way that prevents it from responding to future syscalls.

    This may be thrown by SyscallInterface.
    """
    pass
