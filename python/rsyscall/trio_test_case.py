"A trio-enabled variant of unittest.TestCase"
import trio
import unittest
import functools
from trio._core._run import Nursery

class TrioTestCase(unittest.TestCase):
    "A trio-enabled variant of unittest.TestCase"
    nursery: Nursery

    async def asyncSetUp(self) -> None:
        pass

    async def asyncTearDown(self) -> None:
        pass

    def __init__(self, methodName='runTest') -> None:
        test = getattr(type(self), methodName)
        @functools.wraps(test)
        async def test_with_setup() -> None:
            async with trio.open_nursery() as nursery:
                self.nursery = nursery
                await self.asyncSetUp()
                try:
                    await test(self)
                finally:
                    await self.asyncTearDown()
                nursery.cancel_scope.cancel()
        @functools.wraps(test_with_setup)
        def sync_test_with_setup() -> None:
            trio.run(test_with_setup)
        setattr(self, methodName, sync_test_with_setup)
        super().__init__(methodName)

