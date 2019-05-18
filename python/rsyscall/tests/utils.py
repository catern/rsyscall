import typing as t
import trio
from rsyscall.epoller import Epoller, AsyncFileDescriptor, EpollThread
from rsyscall.memory.ram import RAMThread
from rsyscall.unistd import Pipe

from rsyscall.struct import Bytes

import logging
logger = logging.getLogger(__name__)
# logging.basicConfig(level=logging.DEBUG)

import unittest
async def do_async_things(self: unittest.TestCase, epoller: Epoller, thr: RAMThread) -> None:
    pipe = await (await thr.task.pipe(await thr.ram.malloc_struct(Pipe))).read()
    async_pipe_rfd = await AsyncFileDescriptor.make_handle(epoller, thr.ram, pipe.read)
    async_pipe_wfd = await AsyncFileDescriptor.make_handle(epoller, thr.ram, pipe.write)
    data = b"hello world"
    async def stuff():
        logger.info("async test read: starting")
        result = await async_pipe_rfd.read_some_bytes()
        logger.info("async test read: returned")
        self.assertEqual(result, data)
    async with trio.open_nursery() as nursery:
        nursery.start_soon(stuff)
        await trio.sleep(0.0001)
        # hmmm MMM MMMmmmm MMM mmm MMm mm MM mmm MM mm MM
        # does this make sense?
        logger.info("async test write: starting")
        await async_pipe_wfd.write_all_bytes(data)
        logger.info("async test write: returned")
    await async_pipe_rfd.close()
    await async_pipe_wfd.close()

async def assert_thread_works(self: unittest.TestCase, thr: EpollThread) -> None:
    await do_async_things(self, thr.epoller, thr)
