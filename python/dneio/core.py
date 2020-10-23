"""Async-library-independent shift/reset

Here we provide an abstraction for shift/reset, and resulting continuations,
which works identically across different Python async libraries. Our
implementation of shift/reset is single-shot and single-prompt.

One can call "shift" from any context, and it works identically.  "reset" also
works from any context, but it's a normal non-async function, so that's to be
expected.

Currently we just support trio and "native" continuations produced by calling
shift directly under reset.

As mentioned in the "dneio" module docstring, check out this tutorial if you
aren't familiar with shift/reset:
http://pllab.is.ocha.ac.jp/~asai/cw2011tutorial/main-e.pdf

"""

from __future__ import annotations
from dataclasses import dataclass
from dneio.outcome import Outcome
from trio._core._run import GLOBAL_RUN_CONTEXT, WaitTaskRescheduled, CancelShieldedCheckpoint, PermanentlyDetachCoroutineObject
import abc
import enum
import functools
import logging
import outcome
import trio
import types
import typing as t

__all__ = [
    'shift',
    'reset',
    'Continuation',
    'TrioSystemWaitReadable', 'set_trio_system_wait_readable',
]

logger = logging.getLogger(__name__)

SendType = t.TypeVar('SendType')
ReturnType = t.TypeVar('ReturnType')
AnswerType = t.TypeVar('AnswerType')
YieldType = t.TypeVar('YieldType')

class AnsweringContinuation(t.Generic[AnswerType, SendType, ReturnType]):
    """Something which can be passed SendType once, and produce AnswerType or ReturnType

    This is basically a single-shot function from SendType to ReturnType, except
    that we can also get a value of AnswerType, if the computation calls `shift`.
    Presumably, that `shift` either arranges to store the resulting continuation
    somewhere, or includes it in AnswerType so that the caller can deal with it.

    In practice, we mostly use Continuation, which has None for its answer and
    return types.

    """
    @abc.abstractmethod
    def resume(self, value: Outcome[SendType]) -> t.Union[AnswerType, ReturnType]: ...
    @abc.abstractmethod
    def send(self, value: SendType) -> t.Union[AnswerType, ReturnType]: ...
    @abc.abstractmethod
    def throw(self, exn: BaseException) -> t.Union[AnswerType, ReturnType]: ...
    # right now, everything is cancellable at all times.
    # we'll make this more customizable later.
    @abc.abstractmethod
    def is_cancelled(self) -> bool: ...

    def __call__(self, value: SendType) -> t.Union[AnswerType, ReturnType]:
        return self.send(value)

Continuation = AnsweringContinuation[None, SendType, None]
"""A Continuation whose return and answer types are both None

This is a degenerate form, which is most useful for callbacks registed on some
object, which shouldn't be returning or answering anything to the task invoking
the callback.

Really, this should be called NoneContinuation or something, and
AnswerContinuation should be called Continuation, but this is the more common
form, so it's nice for it to have the shorter name.

"""

class Runner(enum.Enum):
    TRIO = "trio"
    NATIVE = "native"

# For now, we assume we start under trio
_under_coro_runner: Runner = Runner.TRIO

def is_running_directly_under_trio() -> bool:
    return _under_coro_runner == Runner.TRIO


#### Implementation of "native" continuations
class Shift(t.Generic[AnswerType, SendType, ReturnType]):
    "The internal type we yield up to implement the shift function for native coroutines"
    __slots__ = ('func')
    def __init__(self, func: t.Callable[
            [AnsweringContinuation[AnswerType, SendType, ReturnType]], AnswerType]) -> None:
        self.func = func

ShiftCoroutine = t.Coroutine[Shift[AnswerType, SendType, ReturnType], SendType, ReturnType]
"A coroutine which yields Shift. Basically, a 'native' dneio coroutine"

def reset(
        coro: ShiftCoroutine[AnswerType, SendType, ReturnType],
) -> t.Union[AnswerType, ReturnType]:
    "Run this coro such that it can call `shift` and receive its continuation"
    global _under_coro_runner
    try:
        previous_runner = _under_coro_runner
        _under_coro_runner = Runner.NATIVE
        yielded_value: Shift[AnswerType, SendType, ReturnType]
        yielded_value = coro.send(None) # type: ignore
        if not isinstance(yielded_value, Shift):
            coro.throw(TypeError, TypeError("no yielding non-shifts!", yielded_value))
            raise TypeError("coro", coro, "yielded something other than a Shift")
    except StopIteration as e:
        return_value: ReturnType = e.value
        return return_value
    finally:
        _under_coro_runner = previous_runner
    answer_value: AnswerType = yielded_value.func(NativeContinuation(coro))
    return answer_value

@dataclass
class NativeContinuation(AnsweringContinuation[AnswerType, SendType, ReturnType]):
    __slots__ = ('coro')
    coro: ShiftCoroutine[AnswerType, SendType, ReturnType]

    def resume(self, value: Outcome[SendType]) -> t.Union[AnswerType, ReturnType]:
        if isinstance(value, outcome.Value):
            return self.send(value.value)
        else:
            return self.throw(value.error)

    # NativeContinuation.{send,throw} and reset are very similar; they could be
    # abstracted, but that would add stack frames, and keeping them separate is
    # an easy way to remove those stack frames, pending a C implementation.
    def send(self, value: SendType) -> t.Union[AnswerType, ReturnType]:
        global _under_coro_runner
        try:
            previous_runner = _under_coro_runner
            _under_coro_runner = Runner.NATIVE
            yielded_value: Shift[AnswerType, SendType, ReturnType]
            yielded_value = self.coro.send(value)
        except StopIteration as e:
            return_value: ReturnType = e.value
            return return_value
        finally:
            _under_coro_runner = previous_runner
        if not isinstance(yielded_value, Shift):
            self.coro.throw(TypeError("no yielding non-shifts!", yielded_value)) # type: ignore
            raise TypeError("coro", self.coro, "yielded something other than a Shift")
        answer_value: AnswerType = yielded_value.func(NativeContinuation(self.coro))
        return answer_value

    def throw(self, exn: BaseException) -> t.Union[AnswerType, ReturnType]:
        global _under_coro_runner
        try:
            previous_runner = _under_coro_runner
            _under_coro_runner = Runner.NATIVE
            yielded_value: Shift[AnswerType, SendType, ReturnType]
            yielded_value = self.coro.throw(exn) # type: ignore
        except StopIteration as e:
            return_value: ReturnType = e.value
            return return_value
        finally:
            _under_coro_runner = previous_runner
        if not isinstance(yielded_value, Shift):
            self.coro.throw(TypeError("no yielding non-shifts!", yielded_value)) # type: ignore
            raise TypeError("coro", self.coro, "yielded something other than a Shift")
        answer_value: AnswerType = yielded_value.func(NativeContinuation(self.coro))
        return answer_value

    def is_cancelled(self) -> bool:
        return False


#### Implementation of trio continuations
TrioTask = t.Any
"trio doesn't expose the type of Task publicly..."

@dataclass
class TrioContinuation(Continuation[SendType]):
    # We inherit from Continuation not AnsweringContinuation because it's
    # difficult to assign a proper AnswerType to trio tasks - easier for now to just
    # flatly say "None".
    __slots__ = ('task', 'cancelled', 'saved_send')
    task: TrioTask
    cancelled: bool
    saved_send: t.Optional[Outcome[None]]
    on_stack: bool

    # This essentially repeats a large part of the trio run loop. It would be
    # nicer if trio exposed a primtive for this directly.
    def resume(self, value: Outcome[SendType]) -> None:
        if self.cancelled:
            # discard the result - not great, obviously...
            logger.debug("TrioContinuation(%s): resumed after cancellation", self.task)
            return
        if self.on_stack:
            logger.debug("TrioContinuation(%s): immediately resumed with %s", self.task, value)
            # This will happen if the function passed to shift immediately resumes the
            # continuation. With trio, we run the function passed to shift on the
            # coroutine that's being suspended. So we can't resume the coroutine here,
            # since it's already running. Instead we'll save the outcome, and in shift()
            # we check saved_send and just return immediately if it's set. This is not
            # normal shift/reset semantics but it's the best we can do with how trio is
            # structured.
            self.saved_send = value
            return
        resuming_task = GLOBAL_RUN_CONTEXT.task
        runner = GLOBAL_RUN_CONTEXT.runner
        logger.debug("TrioContinuation(%s): resuming with %s", self.task, value)
        global _under_coro_runner
        try:
            previous_runner = _under_coro_runner
            _under_coro_runner = Runner.TRIO
            # We have to temporarily set GLOBAL_RUN_CONTEXT.task to the task that is being
            # resumed; after all, that's the task that's really going to be running. This
            # wouldn't be necessary if we had proper dynamically scoped variables in
            # Python :(
            GLOBAL_RUN_CONTEXT.task = self.task
            # a little bit of reschedule(), before we run the task
            self.task._abort_func = None
            self.task.custom_sleep_data = None
            try:
                msg = self.task.context.run(self.task.coro.send, value)
            except StopIteration as exn:
                logger.debug("TrioContinuation(%s): return %s", self.task, exn.value)
                GLOBAL_RUN_CONTEXT.runner.task_exited(self.task, outcome.Value(exn.value))
                return
            except BaseException as exn:
                logger.debug("TrioContinuation(%s): raised %s", self.task, exn)
                exn = exn.with_traceback(exn.__traceback__ and exn.__traceback__.tb_next)
                GLOBAL_RUN_CONTEXT.runner.task_exited(self.task, outcome.Error(exn))
                return
            logger.debug("TrioContinuation(%s): yield %s", self.task, msg)
        finally:
            _under_coro_runner = previous_runner
            GLOBAL_RUN_CONTEXT.task = resuming_task
        if msg is CancelShieldedCheckpoint:
            runner.reschedule(self.task)
        elif type(msg) is WaitTaskRescheduled:
            self.task._abort_func = msg.abort_func
            if runner.ki_pending and self.task is runner.main_task:
                self.task._attempt_delivery_of_pending_ki()
            self.task._attempt_delivery_of_any_pending_cancel()
        elif type(msg) is PermanentlyDetachCoroutineObject:
            runner.task_exited(self.task, msg.final_outcome)
        else:
            raise TypeError("bad yield from continuation", msg)

    def send(self, value: SendType) -> None:
        return self.resume(outcome.Value(value))

    def throw(self, exn: BaseException) -> None:
        return self.resume(outcome.Error(exn))

    def _abort_func(self, raise_cancel) -> trio.lowlevel.Abort:
        logger.debug("TrioContinuation(%s): cancelled", self.task)
        self.cancelled = True
        return trio.lowlevel.Abort.SUCCEEDED

    def is_cancelled(self) -> bool:
        return self.cancelled

@types.coroutine
def shift(func: t.Callable[[Continuation[SendType]], AnswerType]) -> t.Generator[t.Any, t.Any, SendType]:
    """Call `func` with our current continuation and block until that continuation is resumed.

    This is a coroutine function, just implemented synchronously because this is
    the only place we actually yield from.

    `func` gets a Continuation, not a full-fledged AnsweringContinuation, because
    that's easier to support for now. But in theory `func` should be
    AnsweringContinuation[AnswerType, SendType, ReturnType]

    """
    ensure_system_trio_task_running()
    if _under_coro_runner == Runner.TRIO:
        trio_cont = TrioContinuation[SendType](
            trio.lowlevel.current_task(), False, None,
            on_stack=True,
        )
        # There's no surrounding reset to run `func`, so we just run
        # it here and throw away the answer value.
        func(trio_cont)
        trio_cont.on_stack = False
        if trio_cont.saved_send:
            # the continuation was resumed immediately by func
            return trio_cont.saved_send.unwrap()
        return (yield WaitTaskRescheduled(trio_cont._abort_func)).unwrap()
    elif _under_coro_runner == Runner.NATIVE:
        return (yield Shift(func))
    else:
        raise Exception("running under unsupported coroutine runner")

#### Implementation of non-essential trio system task class
class TrioSystemWaitReadable:
    """Run "wait_readable" in a trio system task so we can avoid blocking trio tasks

    See rsyscall.epoller for how this is used.

    Frustratingly, we have to call .ensure_running on every call to `shift`,
    because trio has no means of autostarting a system task. There has to be a
    better way.

    Note that just calling ensure_running in .wait or .wait_cb doesn't work; a
    coroutine may have already called that in a previous call to trio.run and be
    blocked inside TSWR, waiting for the system task to resume it.

    Before settling on this approach we used a system where `shift` in a trio
    task would automatically open a nursery and make an object much like this
    one, which would automatically be passed down via dynamic scope and magic
    priority inheritance. It fell apart because Python doesn't have proper
    dynamic scope and maintaining the proper inheritance was too hard. That kind
    of implicit, untyped inheritance is against the core idea of dneio anyway;
    at least this object is very explicit and concrete; we don't use it through
    a global variable, we explicitly pass it around. We just need to find a
    better way to support it in trio.

    """
    def __init__(self, fd_number: int) -> None:
        self.fd_number = fd_number
        # we shouldn't ever get more than one waiter
        self._ops_in, self._ops_out = trio.open_memory_channel(1)
        self._run_running = False

    def ensure_running(self) -> None:
        if not self._run_running:
            self._run_running = True
            trio.lowlevel.spawn_system_task(self.run)

    def wait_cb(self, cb: Continuation[None]) -> None:
        self._ops_in.send_nowait(cb)

    async def wait(self) -> None:
        return await shift(self.wait_cb)

    async def run(self) -> None:
        try:
            while True:
                cb = await self._ops_out.receive()
                try:
                    await trio.lowlevel.wait_readable(self.fd_number)
                except:
                    self.wait_cb(cb)
                    raise
                try:
                    cb.send(None)
                except:
                    logger.exception("TSWR.run: callback raised exception")
                    raise
        finally:
            logger.debug("TSWR.run: system task exiting")
            self._run_running = False

_trio_system_wait_readable: t.Optional[TrioSystemWaitReadable] = None

def set_trio_system_wait_readable(tswr: TrioSystemWaitReadable) -> None:
    global _trio_system_wait_readable
    _trio_system_wait_readable = tswr

def ensure_system_trio_task_running() -> None:
    "Called in every call to shift"
    if _trio_system_wait_readable:
        _trio_system_wait_readable.ensure_running()
