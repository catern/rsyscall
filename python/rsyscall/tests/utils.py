import typing as t
import trio
from rsyscall.epoller import Epoller, AsyncFileDescriptor, EpollThread
from rsyscall.memory.ram import RAMThread
from rsyscall.unistd import Pipe
from rsyscall.fcntl import O

import logging
logger = logging.getLogger(__name__)
# logging.basicConfig(level=logging.DEBUG)

import unittest
async def do_async_things(self: unittest.TestCase, epoller: Epoller, thr: RAMThread,
                          *, task_status=trio.TASK_STATUS_IGNORED) -> None:
    logger.info("Setting up for do_async_things")
    pipe = await (await thr.task.pipe(await thr.ram.malloc(Pipe), O.NONBLOCK)).read()
    async_pipe_rfd = await AsyncFileDescriptor.make(epoller, thr.ram, pipe.read)
    async_pipe_wfd = await AsyncFileDescriptor.make(epoller, thr.ram, pipe.write)
    task_status.started(None)
    data = b"hello world"
    logger.info("Starting do_async_things")
    async def stuff():
        logger.info("do_async_things: read: starting on %s", async_pipe_rfd.handle.near)
        result = await async_pipe_rfd.read_some_bytes()
        logger.info("do_async_things: read: returned")
        self.assertEqual(result, data)
    async with trio.open_nursery() as nursery:
        nursery.start_soon(stuff)
        await trio.sleep(0.0001)
        # hmmm MMM MMMmmmm MMM mmm MMm mm MM mmm MM mm MM
        # does this make sense?
        logger.info("do_async_things: write: starting on %s", async_pipe_wfd.handle.near)
        await async_pipe_wfd.write_all_bytes(data)
        logger.info("do_async_things: write: returned")
    await async_pipe_rfd.close()
    await async_pipe_wfd.close()

async def assert_thread_works(self: unittest.TestCase, thr: EpollThread) -> None:
    await do_async_things(self, thr.epoller, thr)
