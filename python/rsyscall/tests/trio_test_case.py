"A trio-enabled variant of unittest.TestCase"
import trio
import unittest
import functools
import types
from trio._core._run import Nursery
from rsyscall import local_thread, Thread
import warnings

class TrioTestCase(unittest.TestCase):
    "A trio-enabled variant of unittest.TestCase"
    nursery: Nursery
    thread: Thread

    async def asyncSetUp(self) -> None:
        "Asynchronously set up resources for tests in this TestCase"
        pass

    async def asyncTearDown(self) -> None:
        "Asynchronously clean up resources for tests in this TestCase"
        pass

    def __init__(self, methodName='runTest') -> None:
        test = getattr(type(self), methodName)
        @functools.wraps(test)
        async def test_with_setup() -> None:
            with warnings.catch_warnings(record=True) as recorded_warnings:
                async with trio.open_nursery() as nursery:
                    self.nursery = nursery
                    self.thr = local_thread
                    await self.asyncSetUp()
                    try:
                        await test(self)
                    except BaseException as exn:
                        try:
                            await self.asyncTearDown()
                        except BaseException as teardown_exn:
                            # have to merge the exceptions if they both throw;
                            # might as well do this with trio.MultiError since we have it
                            raise trio.MultiError([exn, teardown_exn])
                        else:
                            raise
                    else:
                        await self.asyncTearDown()
                    nursery.cancel_scope.cancel()
            # Also throw an exception if there were any "coroutine was
            # never awaited" warnings, to fail the test.
            # See https://github.com/python-trio/pytest-trio/issues/86
            for warning in recorded_warnings:
                if str(warning).endswith('was never awaited'):
                    raise warning # type: ignore
        @functools.wraps(test_with_setup)
        def sync_test_with_setup(self) -> None:
            trio.run(test_with_setup)
        setattr(self, methodName, types.MethodType(sync_test_with_setup, self))
        super().__init__(methodName)

