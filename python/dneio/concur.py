from __future__ import annotations
from dataclasses import dataclass
from dneio import Continuation, shift, reset
from dneio.outcome import Outcome
import functools
import logging
import outcome
import typing as t

logger = logging.getLogger(__name__)

InType = t.TypeVar('InType')
OutType = t.TypeVar('OutType')
T = t.TypeVar('T')

class RequestQueue(t.Generic[InType, OutType]):
    def __init__(self) -> None:
        self._request_cbs: t.List[t.Tuple[InType, Continuation[OutType]]] = []
        self._receiver_cb: t.Optional[Continuation[t.Tuple[InType, Continuation[OutType]]]] = None
        self._final_exn: t.Optional[BaseException] = None

    def close(self, final_exn: BaseException) -> None:
        self._final_exn = final_exn
        request_cbs, self._request_cbs = self._request_cbs, []
        for _, cb in request_cbs:
            cb.throw(self._final_exn)

    def request_cb(self, val: InType, cb: Continuation[OutType]) -> None:
        if self._final_exn:
            logger.debug("RequestQueue.request_cb(%s, %s): throwing final exn %s", val, cb, self._final_exn)
            cb.throw(self._final_exn)
        elif self._receiver_cb:
            logger.debug("RequestQueue.request_cb(%s, %s): waking up receiver_cb %s", val, cb, self._receiver_cb)
            receiver_cb = self._receiver_cb
            self._receiver_cb = None
            receiver_cb.send((val, cb))
        else:
            logger.debug("RequestQueue.request_cb(%s, %s): appending to waiting list of size %d", val, cb, len(self._request_cbs))
            self._request_cbs.append((val, cb))

    async def request(self, val: InType) -> OutType:
        if self._final_exn:
            raise self._final_exn
        logger.debug("RequestQueue.request(%s): shifting into request_cb", val)
        return await shift(functools.partial(self.request_cb, val))

    def get_one_cb(self, cb: Continuation[t.Tuple[InType, Continuation[OutType]]]) -> None:
        assert self._receiver_cb is None
        self._receiver_cb = cb

    async def get_one(self) -> t.Tuple[InType, Continuation[OutType]]:
        if self._request_cbs:
            return self._request_cbs.pop(0)
        else:
            return await shift(self.get_one_cb)

    async def get_many(self) -> t.List[t.Tuple[InType, Continuation[OutType]]]:
        if self._request_cbs:
            ret, self._request_cbs = self._request_cbs, []
            return ret
        else:
            return [await shift(self.get_one_cb)]

    def fetch_any(self) -> t.List[t.Tuple[InType, Continuation[OutType]]]:
        ret, self._request_cbs = self._request_cbs, []
        return ret

class Event:
    def __init__(self) -> None:
        self._waiting_cbs: t.List[Continuation[None]] = []
        self._is_set = False
        self._exc: t.Optional[BaseException] = None

    async def wait(self) -> None:
        if not self._is_set:
            await shift(self._waiting_cbs.append)
        if self._exc:
            raise self._exc

    def set(self) -> None:
        self._is_set = True
        for cb in self._waiting_cbs:
            cb.send(None)

    def close(self, exc: BaseException) -> None:
        self._exc = exc
        self.set()

@dataclass
class Future(t.Generic[T]):
    _result: t.Optional[Outcome[T]] = None
    _result_cb: t.Optional[Continuation[T]] = None

    @staticmethod
    def start(coro: t.Awaitable[T]) -> Future[T]:
        self = Future[T]()
        async def wrapper() -> None:
            result = await outcome.acapture(lambda: coro)
            self._result = result
            if self._result_cb:
                self._result_cb.resume(result)
        wrapper_coro = wrapper()
        wrapper_coro.__name__ = getattr(coro, "__name__", "wrapper")
        wrapper_coro.__qualname__ = getattr(coro, "__qualname__", "wrapper")
        reset(wrapper_coro)
        return self

    def get_cb(self, cb: Continuation[T]) -> None:
        if self._result:
            return cb.resume(self._result)
        assert self._result_cb is None
        self._result_cb = cb

    async def get(self) -> T:
        if self._result:
            return self._result.unwrap()
        return (await shift(self.get_cb))

async def make_n_in_parallel(make: t.Callable[[], t.Awaitable[T]], count: int) -> t.List[T]:
    "Call `make` n times in parallel, and return all the results."
    return [await fut.get() for fut in
            [Future.start(make()) for _ in range(count)]]

T0 = t.TypeVar('T0')
T1 = t.TypeVar('T1')
T2 = t.TypeVar('T2')

# use the same trick that typeshed uses for asyncio.gather to get nice types for run_all
# https://github.com/python/typeshed/pull/1550
@t.overload
async def run_all(a0: t.Awaitable[T0], /) -> tuple[T0]: ...
@t.overload
async def run_all(a0: t.Awaitable[T0], a1: t.Awaitable[T1], /) -> tuple[T0, T1]: ...
@t.overload
async def run_all(a0: t.Awaitable[T0], a1: t.Awaitable[T1], a2: t.Awaitable[T2], /) -> tuple[T0, T1, T2]: ...

# require that all the arguments be of the same type if we're passing more
@t.overload
async def run_all(a0: t.Awaitable[T], a1: t.Awaitable[T], a2: t.Awaitable[T], a3: t.Awaitable[T],
                  /, *arest: t.Awaitable[T]) -> tuple[T]: ...

async def run_all(*awaitables: t.Awaitable) -> tuple:
    "Wait on all the awaitables passed to it, and return all the results."
    futures = [Future.start(aw) for aw in awaitables]
    return tuple([await fut.get() for fut in futures])
