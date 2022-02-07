"A trio-enabled variant of unittest.TestCase"
import trio
import unittest
import contextlib
import functools
import sys
import types
import warnings
from trio._core._run import Nursery
from rsyscall import local_process, Process

@contextlib.contextmanager
def raise_unraisables():
    unraisables = []
    try:
        orig_unraisablehook, sys.unraisablehook = sys.unraisablehook, unraisables.append
        yield
    finally:
        sys.unraisablehook = orig_unraisablehook
        if unraisables:
            raise trio.MultiError([unr.exc_value for unr in unraisables])

class TrioTestCase(unittest.TestCase):
    "A trio-enabled variant of unittest.TestCase"
    nursery: Nursery
    process: Process

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
            self.process = local_process
            async with trio.open_nursery() as nursery:
                self.nursery = nursery
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
        @functools.wraps(test_with_setup)
        def sync_test_with_setup(self) -> None:
            # Throw an exception if there were any "coroutine was never awaited" warnings, to fail the test.
            # See https://github.com/python-trio/pytest-trio/issues/86
            # We also need raise_unraisables, otherwise the exception is suppressed, since it's in __del__
            with raise_unraisables():
                # Restore the old warning filter after the test.
                with warnings.catch_warnings():
                    warnings.filterwarnings('error', message='.*was never awaited', category=RuntimeWarning)
                    trio.run(test_with_setup)
        setattr(self, methodName, types.MethodType(sync_test_with_setup, self))
        super().__init__(methodName)

class Test(unittest.TestCase):
    def test_coro_warning(self) -> None:
        class Test(TrioTestCase):
            async def test(self):
                trio.sleep(0)
        with self.assertRaises(RuntimeWarning):
            Test('test').test()
