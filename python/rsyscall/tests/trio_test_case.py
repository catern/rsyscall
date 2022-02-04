"A trio-enabled variant of unittest.TestCase"
import trio
import unittest
import contextlib
import functools
import gc
import logging
import os
import signal
import sys
import types
import warnings
from rsyscall import local_process, Process
from rsyscall.wish import wish, Wish

logger = logging.getLogger(__name__)

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

def install_handler(sig: signal.Signals) -> None:
    import traceback
    import trio.lowlevel
    existing_handler = signal.getsignal(sig)
    def signal_handler(signo, frame) -> None:
        def walk_coro_stack(coro):
            while coro is not None:
                if hasattr(coro, "cr_frame"):
                    # A real coroutine
                    yield coro.cr_frame, coro.cr_frame.f_lineno
                    coro = coro.cr_await
                elif hasattr(coro, "gi_frame"):
                    # A generator decorated with @types.coroutine
                    yield coro.gi_frame, coro.gi_frame.f_lineno
                    coro = coro.gi_yieldfrom
                else:
                    # this might be an async_generator_asend object;
                    # use hack described in https://bugs.python.org/issue32810#msg335376
                    gen, *rest = gc.get_referents(coro)
                    yield gen.ag_frame, gen.ag_frame.f_lineno
                    coro = gen.ag_await
        def get_children_tasks(task: trio.lowlevel.Task) -> list[trio.lowlevel.Task]:
            return [task for nursery in task.child_nurseries for task in nursery.child_tasks]
        def get_all_tasks() -> list[trio.lowlevel.Task]:
            looking: list[trio.lowlevel.Task] = [trio.lowlevel.current_root_task()]
            found = []
            while looking:
                task = looking.pop(0)
                found.append(task)
                looking.extend(get_children_tasks(task))
            return found
        def stack_in_test(ss: traceback.StackSummary) -> bool:
            return any([fs.name == "test_with_setup" for fs in ss])
        tasks = get_all_tasks()
        tasks_with_stack = [
            (task, traceback.StackSummary.extract(walk_coro_stack(task.coro)))
            for task in tasks
        ]
        # we want to prioritize things which are rooted in the 'test' function
        def prepend_in_test(x: tuple[trio.lowlevel.Task, traceback.StackSummary]) -> str:
            if stack_in_test(x[1]):
                # 1 because we want the test summaries at the bottom (less scrolling)
                return f"1-{x[0].name}"
            else:
                return f"0-{x[0].name}"
        deduped_stacks: dict[tuple[str, str], int] = {}
        for task, stack in sorted(tasks_with_stack, key=prepend_in_test):
            formatted = (task.name, ''.join(stack.format()))
            if formatted not in deduped_stacks:
                deduped_stacks[formatted] = 0
            deduped_stacks[formatted] += 1
        for (taskname, stackstring), count in deduped_stacks.items():
            print(f"============= Coroutine Found :: {taskname} [{count}] ==============\n{stackstring}",
                  file=sys.stderr)
        if existing_handler is not None:
            signal.signal(signo, existing_handler)
            os.kill(os.getpid(), signo)
    # tstest will hit us with a SIGTERM if we interrupt it or timeout
    # it is useful to have some stacks in that case so we print em
    # out here.
    signal.signal(sig, signal_handler)

class TrioTestCase(unittest.TestCase):
    "A trio-enabled variant of unittest.TestCase"
    nursery: trio.Nursery
    process: Process
    stack: contextlib.AsyncExitStack
    suspend_on_failure: bool = False

    async def asyncSetUp(self) -> None:
        "Asynchronously set up resources for tests in this TestCase"
        pass

    async def asyncTearDown(self) -> None:
        "Asynchronously clean up resources for tests in this TestCase"
        pass

    def __init__(self, methodName='runTest') -> None:
        if os.getenv("SUSPEND_ON_FAILURE") == "true":
            self.suspend_on_failure = True
        test = getattr(type(self), methodName)
        @functools.wraps(test)
        async def test_with_setup() -> None:
            # this needs to be installed under trio just in case trio
            # has a handler installed
            install_handler(signal.SIGTERM)
            install_handler(signal.SIGINT)
            self.process = local_process
            async with trio.open_nursery() as nursery:
                self.nursery = nursery
                async with contextlib.AsyncExitStack() as stack:
                    self.stack = stack
                    logger.info("Running asyncSetup...")
                    await self.asyncSetUp()
                    logger.info("...asyncSetup completed successfully, running test...")
                    try:
                        await test(self)
                    except trio.Cancelled as e:
                        raise Exception("Some background task failed and the main test was cancelled") from e
                    except BaseException as exn:
                        if self.suspend_on_failure:
                            await wish(Wish(type(None), "Test run failed"), from_exn=exn)
                        raise exn
                    finally:
                        logger.info("...test completed, running asyncTearDown...")
                        await self.asyncTearDown()
                    logger.info("...asyncTearDown completed successfully, test case passed.")
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
