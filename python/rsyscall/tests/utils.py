import typing as t
import trio
from rsyscall.epoller import Epoller, AsyncFileDescriptor
from rsyscall.unistd import Pipe
from rsyscall.fcntl import O
from rsyscall.thread import Process

import logging
logger = logging.getLogger(__name__)
# logging.basicConfig(level=logging.DEBUG)

import unittest
async def do_async_things(self: unittest.TestCase, epoller: Epoller, thr: Process, i: int=0,
                          *, task_status=trio.TASK_STATUS_IGNORED) -> None:
    logger.debug("Setting up for do_async_things(%d)", i)
    pipe = await (await thr.task.pipe(await thr.task.malloc(Pipe), O.NONBLOCK)).read()
    async_pipe_rfd = await AsyncFileDescriptor.make(epoller, pipe.read)
    async_pipe_wfd = await AsyncFileDescriptor.make(epoller, pipe.write)
    task_status.started(None)
    data = b"hello world"
    logger.debug("Starting do_async_things(%d)", i)
    async def stuff():
        logger.debug("do_async_things(%d): read(%s): starting", i, async_pipe_rfd.handle.near)
        result = await async_pipe_rfd.read_some_bytes()
        logger.debug("do_async_things(%d): read(%s): returned", i, async_pipe_rfd.handle.near)
        self.assertEqual(result, data)
    async with trio.open_nursery() as nursery:
        nursery.start_soon(stuff)
        await trio.sleep(0.0001)
        # hmmm MMM MMMmmmm MMM mmm MMm mm MM mmm MM mm MM
        # does this make sense?
        logger.debug("do_async_things(%d): write(%s): starting", i, async_pipe_wfd.handle.near)
        await async_pipe_wfd.write_all_bytes(data)
        logger.debug("do_async_things(%d): write(%s): returned", i, async_pipe_wfd.handle.near)
    await async_pipe_rfd.close()
    await async_pipe_wfd.close()
    logger.debug("Done with do_async_things(%d)", i)

async def assert_process_works(self: unittest.TestCase, thr: Process) -> None:
    await do_async_things(self, thr.epoller, thr)
