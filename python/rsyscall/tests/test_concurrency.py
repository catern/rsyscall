from dneio import RequestQueue, reset, Event
from rsyscall.tests.trio_test_case import TrioTestCase
import outcome
import trio

class MyException(Exception):
    pass

async def sleep_and_throw() -> None:
    async with trio.open_nursery() as nursery:
        async def thing1() -> None:
            await trio.sleep(0)
            raise MyException("ha ha")
        async def thing2() -> None:
            await trio.sleep(1000)
        nursery.start_soon(thing1)
        nursery.start_soon(thing2)

class TestConcurrency(TrioTestCase):
    async def test_nursery(self) -> None:
        async with trio.open_nursery() as nursery:
            async def a1() -> None:
                await trio.sleep(10)
            async def a2() -> None:
                try:
                    await sleep_and_throw()
                except MyException:
                    pass
                finally:
                    nursery.cancel_scope.cancel()
            nursery.start_soon(a1)
            nursery.start_soon(a2)

    async def test_nest_cancel_inside_shield(self) -> None:
        "If we cancel_scope.cancel() inside a CancelScope which is shielded, it works."
        with trio.CancelScope(shield=True):
            async with trio.open_nursery() as nursery:
                nursery.start_soon(trio.sleep_forever)
                nursery.cancel_scope.cancel()

def failing_function(x):
    raise Exception("failed with", x)

class TestConcur(TrioTestCase):
    async def _first_runner(self, queue: RequestQueue) -> None:
        while True:
            many = await queue.get_many()
            for val, coro in many[::-1]:
                if val == 1337:
                    try:
                        failing_function(x) # type: ignore
                    except Exception as e:
                        coro.resume(outcome.Error(e))
                else:
                    coro.resume(outcome.Value(val + 10))

    async def _second_runner(self, queue: RequestQueue[int, int]) -> None:
        while True:
            many = await queue.get_many()
            for val, coro in many[::-1]:
                try:
                    result = await self.queue.request(val + 100)
                except Exception as e:
                    coro.resume(outcome.Error(e))
                else:
                    coro.resume(outcome.Value(result))

    async def asyncSetUp(self) -> None:
        self.queue = RequestQueue[int, int]()
        reset(self._first_runner(self.queue))
        self.second_queue = RequestQueue[int, int]()
        reset(self._second_runner(self.second_queue))

    async def test_parallel(self) -> None:
        async def req(i: int):
            ret = await self.queue.request(i)
            self.assertEqual(i+10, ret)
        async with trio.open_nursery() as nursery:
            for i in range(3):
                nursery.start_soon(req, i)

    async def test_through_multiple(self) -> None:
        self.assertEqual(await self.second_queue.request(1), 111)

    async def test_event(self) -> None:
        ev = Event()
        async with trio.open_nursery() as nursery:
            @nursery.start_soon
            async def foo():
                await trio.sleep(0)
                ev.set()
            await ev.wait()

    async def test_failure(self) -> None:
        should_fail = 1237
        def length_traceback(tb) -> int:
            if tb is None:
                return 0
            else:
                return 1 + length_traceback(tb.tb_next)
        try:
            await self.second_queue.request(should_fail)
        except Exception as e:
            self.assertLess(length_traceback(e.__traceback__), 10)

