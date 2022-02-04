"A trio-enabled variant of unittest.TestCase"
import io
import os
import signal
import sys
import typing as t
import trio
import unittest
import functools
import types
import gc
import contextlib

from trio._core._run import Nursery
from rsyscall.wish import wish, Wish
from rsyscall import local_process, Process
import logging

logger = logging.getLogger(__name__)

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
        def get_children_tasks(task: trio.lowlevel.Task) -> t.List[trio.lowlevel.Task]:
            return [task for nursery in task.child_nurseries for task in nursery.child_tasks]
        def get_all_tasks() -> t.List[trio.lowlevel.Task]:
            looking: t.List[trio.lowlevel.Task] = [trio.lowlevel.current_root_task()]
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
        def prepend_in_test(x: t.Tuple[trio.lowlevel.Task, traceback.StackSummary]) -> str:
            if stack_in_test(x[1]):
                # 1 because we want the test summaries at the bottom (less scrolling)
                return f"1-{x[0].name}"
            else:
                return f"0-{x[0].name}"
        deduped_stacks: t.Dict[t.Tuple[str, str], int] = {}
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

import warnings

class TrioTestCase(unittest.TestCase):
    "A trio-enabled variant of unittest.TestCase"
    nursery: Nursery
    stack: contextlib.AsyncExitStack
    suspend_on_failure: bool = False
    process: Process

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
            # we convert warnings into exceptions - we do it this way to catch warnings printed from
            # inside destructors, specifically the "coroutine was never awaited" warning
            stored_warnings = []
            orig_showwarning = warnings.showwarning
            def store_and_showwarning(warning, *args, **kwargs) -> None:
                if str(warning).endswith('was never awaited'):
                    # we only care about coroutines for our failing warnings
                    stored_warnings.append(warning)
                orig_showwarning(warning, *args, **kwargs)
            warnings.showwarning = store_and_showwarning # type: ignore
            try:
                async with trio.open_nursery() as nursery:
                    async with contextlib.AsyncExitStack() as stack:
                        self.stack = stack
                        self.nursery = nursery
                        self.process = local_process
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
                        logger.info("...test completed successfully, running asyncTearDown...")
                        await self.asyncTearDown()
                        logger.info("...asyncTearDown completed successfully, test case passed.")
                    nursery.cancel_scope.cancel()
                if stored_warnings:
                    raise Exception(f"Found {len(stored_warnings)} warnings for unawaited coroutines")
            except BaseException as exn:
                # we want to be notified of warnings even if an exception is thrown
                # to make it really obvious we want to color this up if output is a tty
                # if any of our outputs is a tty we will attempt to add this color
                handlers = [
                    handler for handler in logging.getLogger().handlers if isinstance(handler, logging.StreamHandler)
                ]
                streams = [handler.stream for handler in handlers if isinstance(handler.stream, io.TextIOWrapper)]
                is_one_tty = any(stream.isatty() for stream in streams)
                if is_one_tty:
                    color_start = "\033[1;41m"
                    color_end = "\033[1;0m"
                else:
                    color_start = "### "
                    color_end = " ###"
                if stored_warnings:
                    logger.error(f"{color_start}Co-routines which were never awaited:{color_end}")
                    for warning in stored_warnings:
                        logger.error(warning)
                raise exn
        @functools.wraps(test_with_setup)
        def sync_test_with_setup(self) -> None:
            trio.run(test_with_setup)
        setattr(self, methodName, types.MethodType(sync_test_with_setup, self))
        super().__init__(methodName)

