from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import ProcessContext, SubprocessContext, create_current_task, wrap_stdin_out_err
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

    def test_pipe_epoll(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.allocate_epoller(self.task)) as epoller:
                async with (await rsyscall.io.allocate_pipe(self.task)) as pipe:
                    in_data = b"hello"
                    await pipe.wfd.write(in_data)
                    pipe_rfd_wrapped = await epoller.wrap(pipe.rfd)
                    out_data = await pipe_rfd_wrapped.read(len(in_data))
                    self.assertEqual(in_data, out_data)
        trio.run(test)

if __name__ == '__main__':
    import unittest
    unittest.main()


