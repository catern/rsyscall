"Miscellaneous concurrency-management utilities."
import trio
import contextlib
from dataclasses import dataclass
import typing as t
import types

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
class Shift:
    func: t.Callable[[t.Coroutine], t.Any]

@types.coroutine
def _yield(value: t.Any) -> t.Any:
    return (yield value)

async def reset(body: t.Coroutine[t.Any, t.Any, T], next_value: t.Any=None) -> t.Any:
    is_value = True
    next_exn: BaseException
    while True:
        try:
            if is_value:
                yielded_value = body.send(next_value)
            else:
                yielded_value = body.throw(next_exn)
        except StopIteration as e:
            return e.value
        if isinstance(yielded_value, Shift):
            # sure wish I had an effect system to tell me what this value is
            return yielded_value.func(body)
        else:
            try:
                next_value = await _yield(yielded_value)
                is_value = True
            except BaseException as e:
                next_exn = e
                is_value = False

# again, sure wish I had an effect system to constrain this type
async def shift(func: t.Callable[[t.Coroutine], t.Any]) -> t.Any:
    return await _yield(Shift(func))
