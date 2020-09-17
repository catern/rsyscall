"Miscellaneous concurrency-management utilities."
from __future__ import annotations
import trio
import contextlib
from dataclasses import dataclass
import typing as t
import types
import outcome
import logging
import functools
logger = logging.getLogger(__name__)

@dataclass
class OneAtATime:
    """Used as part of multiplexing APIs.

    This class is used to control access to the core work loop of
    multiplexing APIs.

    In a multiplexing API, multiple coroutines want to wait for some
    event; one of the waiting coroutines should be selected to perform
    the actual work of polling for the event.

    A multiplexing API will make a OneAtATime, and when each coroutine
    wants to wait for some event, they will enter the needs_run async
    context manager.

    If needs_run yields true, then that coroutine is the first to be
    waiting, and they need to do the actual work.

    If needs_run yields false, then they should just do nothing; this
    is accomlished with an if-condition. The needs-run context manager
    will handle waiting for the working coroutine to complete their
    work.

    This is different from a lock in that once the coroutine doing the
    work has released the lock, *all* waiting threads are woken up
    instead of just one, like a condition variable. This is important
    because any of the waiting coroutine might have had their work
    done, and no longer need to wait.

    This is different from both a condition variable and a lock in
    that when the threads are woken up, they're informed whether
    someone has already done some work. This is important in our use
    case, where the same coroutines that are waiting for work to be
    done, are also the ones doing the work.

    You could add this information to a condition variable, but it
    would be a separate bit of state that you'd have to maintain; this
    class abstracts it away.

    This is a terrible API, but it works for now.

    A better API would be a "shared coroutine" which runs whenever any
    other coroutine is waiting on it, and is suspended if no other
    coroutine is waiting on it. A shared coroutine also must not
    require entering a contextmanager to create. We should try to get
    that kind of API merged into trio/asyncio.

    This is basically the primitive we need to do "combining", ala
    "flat combining".

    """
    running: t.Optional[trio.Event] = None

    @contextlib.asynccontextmanager
    async def needs_run(self) -> t.AsyncGenerator[bool, None]:
        "Yield a bool indiciating whether the caller should perform the actual work controlled by this OneAtATime."
        if self.running is not None:
            yield False
            await self.running.wait()
        else:
            running = trio.Event()
            self.running = running
            try:
                yield True
            finally:
                self.running = None
                running.set()

class MultiplexedEvent:
    """A one-shot event which, when waited on, selects one waiter to run a callable until it completes.

    The point of this class is that we have multiple callers wanting to wait on the
    completion of a single callable; there's no dedicated thread to run the callable,
    instead it's run directly on the stack of one of the callers. The callable might be
    cancelled, but it will keep being re-run until it successfully completes. Then this
    event is complete; a new one may be created with a new or same callable.

    """
    def __init__(self, try_running: t.Callable[[], t.Awaitable[None]]) -> None:
        self.flag = False
        self.try_running = try_running
        self.one_at_a_time = OneAtATime()

    async def wait(self) -> None:
        "Wait until this event is done, possibly performing work on the event if necessary."
        while not self.flag:
            async with self.one_at_a_time.needs_run() as needs_run:
                if needs_run:
                    # if we successfully complete this call, we set the flag;
                    # exceptions get propagated up to some arbitrary unlucky caller.
                    await self.try_running()
                    self.flag = True

T = t.TypeVar('T')
async def make_n_in_parallel(make: t.Callable[[], t.Awaitable[T]], count: int) -> t.List[T]:
    "Call `make` n times in parallel, and return all the results."
    pairs: t.List[t.Any] = [None]*count
    async with trio.open_nursery() as nursery:
        async def open_nth(n: int) -> None:
            pairs[n] = await make()
        for i in range(count):
            nursery.start_soon(open_nth, i)
    return pairs

async def run_all(callables: t.List[t.Callable[[], t.Awaitable[T]]]) -> t.List[T]:
    "Call all the functions passed to it, and return all the results."
    count = len(callables)
    results: t.List[t.Any] = [None]*count
    async with trio.open_nursery() as nursery:
        async def open_nth(n: int) -> None:
            results[n] = await callables[n]()
        for i in range(count):
            nursery.start_soon(open_nth, i)
    return results

@dataclass
class Future(t.Generic[T]):
    "A value that we might have to wait for."
    _outcome: t.Optional[outcome.Outcome]
    _event: trio.Event

    @staticmethod
    def make() -> t.Tuple[Future, Promise]:
        fut = Future[T](None, trio.Event())
        return fut, Promise(fut)

    async def get(self) -> T:
        await self._event.wait()
        assert self._outcome is not None
        return self._outcome.unwrap()

@dataclass
class Promise(t.Generic[T]):
    "Our promise to provide a value for some Future."
    _future: Future[T]

    def _check_not_set(self) -> None:
        if self._future._outcome is not None:
            raise Exception("Future is already set to", self._future._outcome)

    def send(self, val: T) -> None:
        self._check_not_set()
        self._future._outcome = outcome.Value(val)
        self._future._event.set()

    def throw(self, exn: BaseException) -> None:
        self._check_not_set()
        self._future._outcome = outcome.Error(exn)
        self._future._event.set()

    def set(self, oc: outcome.Outcome) -> None:
        self._check_not_set()
        self._future._outcome = oc
        self._future._event.set()

def make_future() -> t.Tuple[Future, Promise]:
    fut = Future[T](None, trio.Event())
    return fut, Promise(fut)

@dataclass
class FIFOFuture(t.Generic[T]):
    "A value that we might have to wait for."
    _outcome: t.Optional[outcome.Outcome]
    _event: trio.Event
    _retrieved: trio.Event
    _cancel_scope: t.Optional[trio.CancelScope]

    @staticmethod
    def make() -> t.Tuple[FIFOFuture, FIFOPromise]:
        fut = FIFOFuture[T](None, trio.Event(), trio.Event(), None)
        return fut, FIFOPromise(fut)

    async def get(self) -> T:
        await self._event.wait()
        assert self._outcome is not None
        return self._outcome.unwrap()

    def set_retrieved(self):
        if self._cancel_scope:
            self._cancel_scope.cancel()
        self._retrieved.set()

@dataclass
class FIFOPromise(t.Generic[T]):
    "Our promise to provide a value for some Future."
    _future: FIFOFuture[T]

    def set(self, oc: outcome.Outcome) -> None:
        if self._future._outcome is not None:
            raise Exception("Future is already set to", self._future._outcome)
        self._future._outcome = oc
        self._future._event.set()

    async def wait_for_retrieval(self) -> None:
        await self._future._retrieved.wait()

    def set_cancel_scope(self, cancel_scope: trio.CancelScope) -> None:
        self._future._cancel_scope = cancel_scope

@types.coroutine
def _yield(value: t.Any) -> t.Any:
    return (yield value)

@types.coroutine
def _yield_from(coro: t.Any) -> t.Any:
    "Run until started is called"
    return (yield from coro)

@dataclass
class DynvarRequest:
    prompt: Dynvar

def mprint(*args):
    # print(*args)
    pass

class Dynvar(t.Generic[T]):
    async def get(self) -> t.Optional[t.Any]:
        try:
            return await _yield(DynvarRequest(self))
        except (RuntimeError, TypeError) as e:
            # These are what asyncio and trio, respectively, inject on violating the yield protocol
            return None

    async def bind(self, value: T, coro: t.Coroutine) -> t.Any:
        send_value: outcome.Outcome = outcome.Value(None)
        while True:
            try:
                if isinstance(send_value, outcome.Value):
                    yield_value = coro.send(send_value.value)
                else:
                    yield_value = coro.throw(type(send_value.error), send_value.error, send_value.error.__traceback__)
            except StopIteration as e: return e.value
            # handle DynvarRequests for this dynvar, and yield everything else up
            if isinstance(yield_value, DynvarRequest) and yield_value.prompt is self:
                send_value = outcome.Value(value)
            else:
                send_value = (await outcome.acapture(_yield, yield_value))

@dataclass
class SuspendRequest:
    prompt: SuspendableCoroutine
    cancels: t.List[trio.Cancelled]

class SuspendableCoroutine:
    def __init__(self, run_func: t.Callable[[SuspendableCoroutine], t.Coroutine]) -> None:
        self._coro: t.Coroutine = run_func(self)
        self._run_func = run_func
        self._lock = trio.Lock()
        self._outcome = None

    def __del__(self) -> None:
        # suppress the warning about unawaited coroutine that we'd get
        # if we never got the chance to drive this coro
        try:
            self._coro.close()
        except RuntimeError as e:
            if "generator didn't stop after throw" in str(e):
                # hack-around pending python 3.7.9 upgrade
                pass
            else:
                raise

    @staticmethod
    async def start(run_func: t.Callable[[SuspendableCoroutine], t.Coroutine]) -> SuspendableCoroutine:
        async def wrapper(susp: SuspendableCoroutine) -> None:
            out = await outcome.acapture(run_func, susp)
            self._outcome = out
        self = SuspendableCoroutine(wrapper)
        await self.drive()
        return self

    async def get(self) -> t.Any:
        while True:
            if self._outcome:
                return self._outcome.unwrap()
            await self.drive()

    async def drive(self) -> t.Any:
        async with self._lock:
            if self._outcome:
                return self._outcome.unwrap()
            await trio.sleep(0)
            send_value: outcome.Outcome = outcome.Value(None)
            while True:
                try: yield_value = send_value.send(self._coro)
                except StopIteration as e:
                    # logger.info("Done with send in %s, returned %s", self, e.value)
                    return e.value
                except BaseException as e:
                    # logger.info("Got exn %s", e)
                    raise
                # handle SuspendRequests for us, and yield everything else up
                if isinstance(yield_value, SuspendRequest) and yield_value.prompt is self:
                    if yield_value.cancels:
                        raise trio.MultiError(yield_value.cancels)
                    else:
                        return
                else:
                    send_value = (await outcome.acapture(_yield, yield_value))

    @contextlib.asynccontextmanager
    async def running(self) -> t.AsyncIterator[None]:
        done = False
        def handle_cancelled(exn: BaseException) -> t.Optional[BaseException]:
            # logger.info("Handling %s", exn)
            if isinstance(exn, trio.Cancelled) and done:
                return None
            else:
                return exn
        with trio.MultiError.catch(handle_cancelled):
            async with trio.open_nursery() as nursery:
                nursery.start_soon(self.drive)
                yield
                # logger.info("Done with yield in running for %s", self)
                done = True
                nursery.cancel_scope.cancel()
            # logger.info("Done with nursery")

    async def suspend(self) -> None:
        await _yield(SuspendRequest(self, []))

    @contextlib.asynccontextmanager
    async def suspend_if_cancelled(self) -> t.AsyncIterator[None]:
        cancels = []
        def handle_cancelled(exn: BaseException) -> t.Optional[BaseException]:
            if isinstance(exn, trio.Cancelled):
                cancels.append(exn)
                return None
            else:
                return exn
        with trio.MultiError.catch(handle_cancelled):
            yield
        if cancels:
            await _yield(SuspendRequest(self, cancels))

    async def with_running(self, func: t.Callable[[], t.Awaitable[t.Any]]) -> t.Any:
        async with self.running():
            return await func()

    async def wait(self, func: t.Callable[[], t.Any]) -> t.Any:
        while True:
            async with self.suspend_if_cancelled():
                return await func()
import math

YieldType = t.TypeVar('YieldType')
SendType = t.TypeVar('SendType')
ReturnType = t.TypeVar('ReturnType')
AnswerType = t.TypeVar('AnswerType')

class Shift(t.Generic[SendType, ReturnType, AnswerType]):
    def __init__(self,
                 func: t.Callable[[t.Coroutine[Shift[SendType, ReturnType, AnswerType], SendType, ReturnType]], AnswerType],
    ) -> None:
        self.func = func

ShiftCoroutine = t.Coroutine[Shift[SendType, ReturnType, AnswerType], SendType, ReturnType]

class Outcome(t.Generic[T], outcome.Outcome):
    pass

def reset(
        body: t.Coroutine[Shift[SendType, ReturnType, AnswerType], SendType, ReturnType],
        value: Outcome[SendType],
) -> t.Union[ReturnType, AnswerType]:
    try:
        if isinstance(value, outcome.Value):
            yielded_value = body.send(value.value)
        else:
            yielded_value = body.throw(type(value.error), value.error, value.error.__traceback__)
    except StopIteration as e:
        return e.value
    if isinstance(yielded_value, Shift):
        # sure wish I had an effect system to tell me what this value is
        return yielded_value.func(body)
    else:
        body.throw(TypeError, TypeError("no yielding non-shifts!"))
        raise TypeError("coro", body, "yielded something other than a Shift")

# again, sure wish I had an effect system to constrain this type
async def shift(
        func: t.Callable[[
            t.Coroutine[Shift[SendType, ReturnType, AnswerType], SendType, ReturnType]
        ], AnswerType],
) -> SendType:
    return await _yield(Shift(func))

Continuation = t.Coroutine[Shift[T, None, None], T, None]

import abc

class TemporaryFailure(Exception):
    pass

class TrioRunner:
    @abc.abstractmethod
    async def immediate_trio_op(self, op: t.Callable[..., t.Awaitable[T]], *args: t.Any) -> T:
        pass

    @abc.abstractmethod
    async def trio_op(self, op: t.Callable[..., t.Awaitable[T]], *args: t.Any) -> T:
        pass

    def add_delegator(self, runner: TrioRunner) -> None:
        "Runner `self` will now receive delegated trio_ops from `runner`."
        pass

    def remove_delegator(self, runner: TrioRunner) -> None:
        "Runner `self` will no longer received delegated trio_ops from `runner`."
        pass

    def retry_delegatee(self, runner: TrioRunner) -> None:
        "Runner `runner`, which we delegate to, is newly able to perform ops, so we should try using it again."
        pass

class SingleTrioRunner(TrioRunner):
    def __init__(self) -> None:
        self._ops_in, self._ops_out = trio.open_memory_channel(math.inf)
        self._cancelled: t.Optional[BaseException] = None

    def _add_op(self, op: t.Callable[..., t.Awaitable[T]], args: t.List[t.Any], coro: Continuation[T]) -> None:
        mprint("sending to ops_in on single", op)
        self._ops_in.send_nowait((op, args, coro))

    async def immediate_trio_op(self, op: t.Callable[..., t.Awaitable[T]], *args: t.Any) -> T:
        if self._cancelled:
            raise self._cancelled
        logger.info("STR.imm_trio_op: %s", op)
        return await shift(functools.partial(self._add_op, op, args))

    async def trio_op(self, op: t.Callable[..., t.Awaitable[T]], *args: t.Any) -> T:
        return await self.immediate_trio_op(op, *args)

    async def run(self) -> None:
        async with self._ops_out:
            try:
                async with trio.open_nursery() as nursery:
                    while True:
                        async def do_op(op: t.Callable[..., t.Awaitable[T]], args: t.List[t.Any], coro: t.Coroutine) -> None:
                            logger.info("STR.do_op: %s", op)
                            result = await outcome.acapture(op, *args)
                            mprint("result from op", op, "is", result)
                            reset(coro, result)
                        mprint("calling ops_out.receive()", self)
                        op, args, coro = await self._ops_out.receive()
                        mprint("got from ops_out", self, op, coro)
                        nursery.start_soon(do_op, op, args, coro)
            except BaseException as exn:
                mprint("single runner was cancelled", self)
                self._cancelled = exn
                # send this cancelled to everything waiting on us to perform their trio ops
                while True:
                    try:
                        op, args, coro = self._ops_out.receive_nowait()
                    except trio.WouldBlock:
                        break
                    reset(coro, outcome.Error(exn))
                raise

class CombinedTrioRunner(TrioRunner):
    def __init__(self) -> None:
        self._backends: t.List[TrioRunner] = []
        self._waiting_for_backends: t.List[Continuation[None]] = []
        self._delegators: t.List[TrioRunner] = []
        self._active_backends: t.List[TrioRunner] = []

    def _wait_for_more_backends(self, coro: Continuation[None]) -> None:
        mprint("appending", coro)
        self._waiting_for_backends.append(coro)
    
    def _wake_up_waiters(self) -> None:
        waiting = self._waiting_for_backends
        self._waiting_for_backends = []
        for coro in waiting:
            # resume all these coros, their wait is over - a new backend is here!
            logger.debug("waking up %s", coro)
            reset(coro, outcome.Value(None))

    def add_delegator(self, backend: TrioRunner) -> None:
        self._delegators.append(backend)

    def remove_delegator(self, backend: TrioRunner) -> None:
        self._delegators.remove(backend)

    def retry_delegatee(self, backend: TrioRunner) -> None:
        self._active_backends.append(backend)
        # just blindly wake up and retry everything
        self._wake_up_waiters()
        for delegator in self._delegators:
            delegator.retry_delegatee(self)

    def add_backend(self, backend: TrioRunner) -> None:
        logger.debug("adding backend %s", backend)
        assert not (self._waiting_for_backends and self._active_backends)
        backend.add_delegator(self)
        self._backends.append(backend)
        self._active_backends.append(backend)
        self.retry_delegatee(backend)

    def remove_backend(self, backend: TrioRunner) -> None:
        backend.remove_delegator(self)
        try:
            self._backends.remove(backend)
        except ValueError:
            pass
        try:
            self._active_backends.remove(backend)
        except ValueError:
            pass

    def deactivate_backend(self, backend: TrioRunner) -> None:
        self._active_backends.remove(backend)

    async def immediate_trio_op(self, op: t.Callable[..., t.Awaitable[T]], *args: t.Any) -> T:
        mprint("doing an immediate_trio_op")
        # hmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
        # certain backends, we shouldn't retry.
        # very interesting.
        # so I mean... we want to temporarily disable certain backends I guess.
        # so... this should be a list of active delegatees...?
        # no, we're still delegated.
        # I guess we'll add delegatees.
        # aha and we'll readd the list in retry_delegatee
        while self._active_backends:
            mprint("backends", self._active_backends)
            for backend in list(self._active_backends):
                def handle(exn: BaseException) -> t.Optional[BaseException]:
                    if isinstance(exn, trio.Cancelled):
                        mprint("backend was cancelled:", backend)
                        # it's not gonna get uncancelled, remove it
                        self.remove_backend(backend)
                    elif isinstance(exn, TemporaryFailure):
                        mprint("backend was temporarily broken", backend)
                        self.deactivate_backend(backend)
                    else:
                        return exn
                    return None
                with trio.MultiError.catch(handle):
                    mprint("trying backend", backend, "with", op)
                    ret = await backend.immediate_trio_op(op, *args)
                    mprint("got ret", ret, "from", op)
                    return ret
        mprint("can't do a trio_op, throwing")
        raise TemporaryFailure()

    async def trio_op(self, op: t.Callable[..., t.Awaitable[T]], *args: t.Any) -> T:
        mprint("doing a trio_op", op)
        while True:
            try:
                return await self.immediate_trio_op(op, *args)
            except TemporaryFailure:
                mprint("got tempfailure")
                pass
            logger.info("Cbined.trio_op: waiting for a backend for %s", op.__qualname__)
            # there are no working backends.
            # shift and store our coro so that we get run when a new backend is added
            await shift(self._wait_for_more_backends)
            logger.info("Cbined.trio_op: woke up for %s", op.__qualname__)
            mprint("woke up, more backends, time to try again")

trio_runner: Dynvar[t.Optional[TrioRunner]] = Dynvar()

async def trio_op(op: t.Callable[..., t.Awaitable[T]], *args: t.Any) -> T:
    runner = await trio_runner.get()
    if runner:
        logger.info("trio_op: %s", op.__qualname__)
        ret = await runner.trio_op(op, *args)
        logger.info("trio_op: returning from %s", op.__qualname__)
        return ret
    else:
        # just try to do it directly
        logger.info("trio_op: directly doing %s", op.__qualname__)
        return await op(*args)

async def start_future(nursery, coro: t.Coroutine) -> Future:
    future, promise = Future.make()
    async def wrapper():
        promise.set(outcome.acapture(_yield_from, coro))
    runner = SingleTrioRunner()
    nursery.start_soon(runner.run)
    # start the coro
    reset(trio_runner.bind(runner, wrapper()), outcome.Value(None))
    return future

async def run_in_wrapper(coro: ShiftCoroutine[None, ReturnType, None]) -> ReturnType:
    future, promise = Future.make()
    async def wrapper():
        promise.set(await outcome.acapture(_yield_from, coro))
    runner = SingleTrioRunner()
    # start the coro outside, because nursery entry is a checkpoint...
    reset(trio_runner.bind(runner, wrapper()), outcome.Value(None))
    async with trio.open_nursery() as nursery:
        nursery.start_soon(runner.run)
        try:
            result = await future.get()
        except BaseException as e:
            mprint("run_in_wrapper got", e)
            raise
        nursery.cancel_scope.cancel()
    return result

InType = t.TypeVar('InType')
OutType = t.TypeVar('OutType')
import traceback
class CoroQueue(t.Generic[InType, OutType]):
    def __init__(self) -> None:
        self._waiting: t.List[t.Tuple[InType, Continuation[OutType]]] = []
        self._receiver_coro: t.Optional[Continuation[t.Tuple[InType, Continuation[OutType]]]] = None
        self._trio_runner = CombinedTrioRunner()
        self._backends: t.Dict[Continuation[OutType], TrioRunner] = {}
        self._dead = False

    @staticmethod
    def start(run_func: t.Callable[[CoroQueue[InType, OutType]], ShiftCoroutine[None, None, None]]) -> CoroQueue[InType, OutType]:
        self = CoroQueue[InType, OutType]()
        reset(trio_runner.bind(self._trio_runner, self._begin_running(run_func)), outcome.Value(None))
        return self

    async def _begin_running(
            self, run_func: t.Callable[[CoroQueue[InType, OutType]], ShiftCoroutine[None, None, None]],
    ) -> None:
        try:
            await run_func(self)
        except GeneratorExit:
            # this indicates we've been GC'd, we can't safely touch anything here;
            # fortunately, the _waiting coros will likely be GC'd also soon.
            pass
        except BaseException as e:
            self._dead = True
            waiting_coros = self._waiting
            self._waiting = []
            for val, waiting in waiting_coros:
                try:
                    reset(waiting, outcome.Error(e))
                except:
                    logger.exception("Coro %s", waiting, "raised while shutting it down")
            raise
        else:
            self._dead = True
            for val, waiting in self._waiting:
                try:
                    reset(waiting, outcome.Error(Exception("the coroqueue we were waiting on is ded :(")))
                except:
                    logger.exception("Coro %s", waiting, "raised while shutting it down")

    def register_request(self, val: InType, trio_runner: TrioRunner,
                         coro: Continuation[OutType],
    ) -> None:
        logger.info("CoroQueue.register_request: %s %s", val, coro)
        if self._dead:
            reset(coro, outcome.Error(Exception("the coroqueue we were waiting on is ded :(")))
            return
        self._backends[coro] = trio_runner
        self._trio_runner.add_backend(trio_runner)
        if self._receiver_coro:
            receiver_coro = self._receiver_coro
            self._receiver_coro = None
            mprint("waking up receiver coro")
            reset(receiver_coro, outcome.Value((val, coro)))
        else:
            self._waiting.append((val, coro))

    def forward_request(self, queue: CoroQueue[T, OutType], val: T,
                        coro: Continuation[OutType],
    ) -> None:
        backend = self._backends[coro]
        self._trio_runner.remove_backend(backend)
        del self._backends[coro]
        queue.register_request(val, backend, coro)

    async def send_request(self, val: InType) -> OutType:
        if self._dead:
            raise Exception("the coroqueue we were waiting on is ded :(")
        logger.info("CoroQueue.send_request: starting send_request for %s", val)
        runner = await trio_runner.get()
        if runner:
            logger.info("CoroQueue.send_request: shifting into register_request for %s", val)
            return await shift(functools.partial(self.register_request, val, runner))
        else:
            # this must be a regular trio task
            logger.info("CoroQueue.send_request: running in wrapper for %s", val)
            return await run_in_wrapper(self.send_request(val))

    def _start_wait_for_one(self, coro: Continuation[t.Tuple[InType, Continuation[OutType]]]) -> None:
        assert self._receiver_coro is None
        self._receiver_coro = coro

    async def get_one(self) -> t.Tuple[InType, Continuation[OutType]]:
        if self._waiting:
            return self._waiting.pop(0)
        else:
            return await shift(self._start_wait_for_one)

    async def get_many(self) -> t.List[t.Tuple[InType, Continuation[OutType]]]:
        if self._waiting:
            ret = self._waiting
            self._waiting = []
            return ret
        else:
            return [await shift(self._start_wait_for_one)]

    def fetch_any(self) -> t.List[t.Tuple[InType, Continuation[OutType]]]:
        ret = self._waiting
        self._waiting = []
        return ret

    def fill_request(self, coro: Continuation[OutType],
                     result: Outcome[OutType]) -> None:
        logger.info("CoroQueue.fill_request: %s %s", result, coro)
        backend = self._backends[coro]
        self._trio_runner.remove_backend(backend)
        del self._backends[coro]
        reset(coro, result)
