from rsyscall.trio_test_case import TrioTestCase
from rsyscall.near.sysif import syscall_future
from rsyscall.concurrency import SuspendableCoroutine
import trio
import logging
logger = logging.getLogger(__name__)

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

import rsyscall.tasks.local as local

class TestConnectionConcurrency(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = await local.thread.clone()

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_future_getpid(self) -> None:
        fut1 = await syscall_future(self.thr.task.getpid())
        fut2 = await syscall_future(self.thr.task.getpid())
        result2 = await fut2.get()
        result1 = await fut1.get()
        self.assertEqual(result1, self.thr.process.process.near)
        self.assertEqual(result2, self.thr.process.process.near)

from rsyscall.concurrency import CoroQueue, trio_op
import outcome

async def runner(queue: CoroQueue) -> None:
    while True:
        await trio_op(lambda: trio.sleep(0))
        many = await queue.get_many()
        await trio_op(lambda: trio.sleep(0))
        print("got many", many)
        for val, coro in many[::-1]:
            queue.fill_request(coro, outcome.Value(val + 10))

class TestCoroQueue(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.queue = CoroQueue.start(runner)
        self.second_queue = CoroQueue.start(self._second_runner)

    async def _second_runner(self, queue: CoroQueue) -> None:
        while True:
            await trio_op(lambda: trio.sleep(0))
            many = await queue.get_many()
            await trio_op(lambda: trio.sleep(0))
            for val, coro in many[::-1]:
                result = await self.queue.send_request(val + 100)
                queue.fill_request(coro, outcome.Value(result))

    async def test_queue(self) -> None:
        async def req(i: int):
            print("req for", i)
            ret = await self.queue.send_request(i)
            print("return value for", i, "is", ret)
            self.assertEqual(i+10, ret)
        async with trio.open_nursery() as nursery:
            for i in range(3):
                nursery.start_soon(req, i)

    async def test_inheritance(self) -> None:
        print('result', await self.second_queue.send_request(1))
