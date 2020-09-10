from rsyscall.trio_test_case import TrioTestCase
from rsyscall.near.sysif import syscall_snd_callback
from rsyscall.concurrency import StartedFuture
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
        fut = await StartedFuture.start(lambda fut: syscall_snd_callback.bind(fut.started, self.thr.task.getpid()))
        result = await fut.run()
        print(result)
        fut = await StartedFuture.start(lambda fut: syscall_snd_callback.bind(fut.started, self.thr.task.getpid()))
        result = await fut.run()
        print(result)
