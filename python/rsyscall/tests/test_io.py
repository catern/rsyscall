from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import ProcessContext, SubprocessContext
import unittest
import supervise_api
import trio
import trio.hazmat
import rsyscall.io
import os

class TestIO(unittest.TestCase):
    def setUp(self):
        self.syscall = rsyscall.io.LocalSyscall(trio.hazmat.wait_readable)

    def test_pipe(self):
        async def test() -> None:
            async with (await rsyscall.io.allocate_pipe(self.syscall)) as pipe:
                in_data = b"hello"
                await pipe.wfd.write(in_data)
                out_data = await pipe.rfd.read(len(in_data))
                self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_subprocess(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.syscall) as subproc:
                await subproc.exit(0)
        trio.run(test)

    def test_subprocess_nested(self):
        async def test() -> None:
            async with rsyscall.io.subprocess(self.syscall):
                async with rsyscall.io.subprocess(syscall) as subproc:
                    await subproc.exit(0)
        trio.run(test)

if __name__ == '__main__':
    import unittest
    unittest.main()


