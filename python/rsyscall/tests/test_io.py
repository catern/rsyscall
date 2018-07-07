from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import ProcessContext, SubprocessContext, create_current_task, wrap_stdin_out_err
from rsyscall.io import Epoller, allocate_epoll, AsyncFileDescriptor
from rsyscall.epoll import EpollEvent, EpollEventMask
import unittest
import supervise_api
import trio
import trio.hazmat
import rsyscall.io
import os
import logging

logging.basicConfig(level=logging.DEBUG)

class TestIO(unittest.TestCase):
    def setUp(self):
        self.task = create_current_task()
        streams = wrap_stdin_out_err(self.task)
        self.stdin = streams.stdin
        self.stdout = streams.stdout
        self.stderr = streams.stderr

    def test_pipe(self):
        async def test() -> None:
            async with (await rsyscall.io.allocate_pipe(self.task)) as pipe:
                in_data = b"hello"
                await pipe.wfd.write(in_data)
                out_data = await pipe.rfd.read(len(in_data))
                self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_subprocess(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.task) as subproc:
                await subproc.exit(0)
        trio.run(test)

    def test_subprocess_fcntl(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.task) as subproc:
                await subproc.exit(0)
        trio.run(test)

    def test_subprocess_nested(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.task):
                async with rsyscall.io.subprocess(self.task) as subproc:
                    await subproc.exit(0)
        trio.run(test)

    def test_cat(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_in:
                async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_out:
                    async with rsyscall.io.subprocess(self.task) as subproc:
                        await subproc.translate(pipe_in.rfd).dup2(subproc.translate(self.stdin))
                        await subproc.translate(pipe_out.wfd).dup2(subproc.translate(self.stdout))
                        await subproc.exec("/bin/sh", ['sh', '-c', 'cat'])
                    in_data = b"hello"
                    await pipe_in.wfd.write(in_data)
                    out_data = await pipe_out.rfd.read(len(in_data))
                    self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_cat(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_in:
                    async with (await rsyscall.io.allocate_pipe(self.task)) as pipe_out:
                        async with rsyscall.io.subprocess(self.task) as subproc:
                            await subproc.translate(pipe_in.rfd).dup2(subproc.translate(self.stdin))
                            await subproc.translate(pipe_out.wfd).dup2(subproc.translate(self.stdout))
                            await subproc.exec("/bin/sh", ['sh', '-c', 'cat'])
                        async_cat_rfd = await AsyncFileDescriptor.make(epoller, pipe_out.rfd)
                        async_cat_wfd = await AsyncFileDescriptor.make(epoller, pipe_in.wfd)
                        in_data = b"hello world"
                        await async_cat_wfd.write(in_data)
                        out_data = await async_cat_rfd.read()
                        self.assertEqual(in_data, out_data)
        trio.run(test)

    async def do_epoll_things(self, epoller) -> None:
        async with (await rsyscall.io.allocate_pipe(self.task)) as pipe:
            pipe_rfd_wrapped = await epoller.add(pipe.rfd, EpollEventMask.make(in_=True))
            async def stuff():
                events = await pipe_rfd_wrapped.wait()
                self.assertEqual(len(events), 1)
                self.assertTrue(events[0].in_)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(stuff)
                await trio.sleep(0)
                await pipe.wfd.write(b"data")

    def test_epoll(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                await self.do_epoll_things(epoller)
        trio.run(test)

    def test_epoll_multi(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with trio.open_nursery() as nursery:
                    for i in range(5):
                        nursery.start_soon(self.do_epoll_things, epoller)
        trio.run(test)

    async def do_async_things(self, epoller) -> None:
        async with (await rsyscall.io.allocate_pipe(self.task)) as pipe:
            async_pipe_rfd = await AsyncFileDescriptor.make(epoller, pipe.rfd)
            async_pipe_wfd = await AsyncFileDescriptor.make(epoller, pipe.wfd)
            data = b"hello world"
            async def stuff():
                result = await async_pipe_rfd.read()
                self.assertEqual(result, data)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(stuff)
                await trio.sleep(0)
                await async_pipe_wfd.write(data)

    def test_async(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                await self.do_async_things(epoller)
        trio.run(test)

    def test_async_multi(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoll(self.task)) as epoll:
                epoller = Epoller(epoll)
                async with trio.open_nursery() as nursery:
                    for i in range(5):
                        nursery.start_soon(self.do_async_things, epoller)
        trio.run(test)

if __name__ == '__main__':
    import unittest
    unittest.main()


