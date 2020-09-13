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
            try: yield_value = send_value.send(coro)
            except StopIteration as e: return e.value
            # handle DynvarRequests for this dynvar, and yield everything else up
            if isinstance(yield_value, DynvarRequest) and yield_value.prompt is self:
                send_value = outcome.Value(value)
            else:
                send_value = (await outcome.acapture(_yield, yield_value))
@dataclass
class StartedFutureRequest:
    prompt: StartedFuture

class StartedFuture:
    def __init__(self, run_func: t.Callable[[StartedFuture], t.Coroutine]) -> None:
        self._coro: t.Coroutine = run_func(self)
        self._run_func = run_func

    async def started(self) -> None:
        await _yield(StartedFutureRequest(self))

    @staticmethod
    async def start(run_func: t.Callable[[StartedFuture], t.Coroutine]) -> StartedFuture:
        self = StartedFuture(run_func)
        await self.run_initial()
        return self

    async def run_initial(self) -> None:
        "Run until started is called"
        send_value: outcome.Outcome = outcome.Value(None)
        while True:
            try: yield_value = send_value.send(self._coro)
            except StopIteration as e:
                raise Exception("StartedFuture function returned without calling started, value:", e.value)
            if isinstance(yield_value, StartedFutureRequest) and yield_value.prompt is self:
                return
            else:
                send_value = (await outcome.acapture(_yield, yield_value))

    async def run(self) -> t.Any:
        "Run until started is called"
        # We don't need to intercept any more requests, nice.
        return await _yield_from(self._coro)

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
                    logger.info("Done with send in %s, returned %s", self, e.value)
                    return e.value
                except BaseException as e:
                    logger.info("Got exn %s", e)
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
            logger.info("Handling %s", exn)
            if isinstance(exn, trio.Cancelled) and done:
                return None
            else:
                return exn
        with trio.MultiError.catch(handle_cancelled):
            async with trio.open_nursery() as nursery:
                nursery.start_soon(self.drive)
                yield
                logger.info("Done with yield in running for %s", self)
                done = True
                nursery.cancel_scope.cancel()
            logger.info("Done with nursery")

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
@dataclass
class SuspendRequest:
    prompt: SuspendableCoroutine
    cancels: t.List[trio.Cancelled]

@dataclass
class Shift:
    func: t.Callable[[t.Coroutine], t.Any]

def reset(body: t.Coroutine[t.Any, t.Any, T], value: outcome.Outcome) -> t.Any:
    try:
        yielded_value = value.send(body)
    except StopIteration as e:
        return e.value
    if isinstance(yielded_value, Shift):
        # sure wish I had an effect system to tell me what this value is
        return yielded_value.func(body) # type: ignore
    else:
        body.throw(TypeError("no yielding non-shifts!"))

# again, sure wish I had an effect system to constrain this type
async def shift(func: t.Callable[[t.Coroutine], t.Any]) -> t.Any:
    return await _yield(Shift(func))

class TrioRunner:
    def __init__(self) -> None:
        self._ops_in, self._ops_out = trio.open_memory_channel(math.inf)

    def _add_op(self, op: t.Callable[[], t.Coroutine], coro: t.Coroutine) -> None:
        self._ops_in.send_nowait((op, coro))

    async def trio_op(self, op: t.Callable[[], t.Coroutine]) -> t.Any:
        await shift(lambda coro: self._add_op(op, coro))

    async def drive(self) -> t.Any:
        while True:
            op, coro = await self._ops_out.receive()
            result = await outcome.acapture(op)
            if isinstance(result, outcome.Error) and isinstance(result.error, trio.Cancelled):
                # if we get cancelled, we don't inject that into the coro; we just retry later.
                self._ops_in.send_nowait((op, coro))
                raise result.error
            reset(coro, outcome)

async def start_future(nursery, coro: t.Coroutine) -> Future:
    future, promise = Future.make()
    async def wrapper():
        promise.set(outcome.acapture(_yield_from, coro))
    runner = TrioRunner()
    # start the coro
    reset(trio_runner.bind(runner, wrapper()), outcome.Value(None))
    return future

class CoroQueue:
    def register_request(self, val: t.Any, coro: t.Coroutine) -> None:
        if self._receiver_coro:
            coro = self._receiver_coro
            self._receiver_coro = None
            self._receiver_coro.send((val, coro))
        else:
            self._waiting.append((val, coro))

    async def send_request(self, val: t.Any) -> t.Any:
        await shift(functools.partial(self._send_request, val))

    async def _start_wait_for_one(self, coro: t.Coroutine) -> None:
        assert self._receiver_coro is None
        self._receiver_coro = coro

    async def get_one(self) -> t.Tuple[[t.Any, t.Coroutine]]:
        if self._waiting:
            return self._waiting.popleft()
        else:
            return await shift(self._start_wait_for_one)

    async def get_many(self) -> t.List[t.Tuple[[t.Any, t.Coroutine]]]:
        if self._waiting:
            ret = self._waiting
            self._waiting = None
            return ret
        else:
            return [await shift(self._start_wait_for_one)]

