from rsyscall.trio_test_case import TrioTestCase
import trio

class TestException(Exception):
    pass

async def sleep_and_throw() -> None:
    async with trio.open_nursery() as nursery:
        async def thing1() -> None:
            await trio.sleep(0)
            raise TestException("ha ha")
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
                except TestException:
                    pass
                finally:
                    nursery.cancel_scope.cancel()
            nursery.start_soon(a1)
            nursery.start_soon(a2)
