from rsyscall.trio_test_case import TrioTestCase
from rsyscall.concurrency import shift, reset
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

    async def test_shift_reset(self) -> None:
        val = 42
        sendval = 123
        async def func() -> int:
            logger.info("About to sleep for the first time")
            await trio.sleep(0)
            logger.info("shifting...")
            shiftval = await shift(lambda coro: coro)
            logger.info("...returned %s from shifting.", shiftval)
            self.assertEqual(shiftval, sendval)
            logger.info("Sleeping a second time.")
            await trio.sleep(0)
            logger.info("Returning %s from coroutine function.", val)
            return val
        logger.info("Creating coroutine object.")
        coro = func()
        logger.info("Passing coroutine object to reset.")
        suspended_func = await reset(coro)
        logger.info("Got back suspended coroutine, resuming it with reset, "
                    "sending value %s", sendval)
        retval = await reset(suspended_func, next_value=sendval)
        logger.info("Got back final return value %s.", retval)
        self.assertEqual(val, retval)
