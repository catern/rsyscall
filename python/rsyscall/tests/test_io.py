from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import ProcessContext, SubprocessContext
import unittest
import supervise_api
import trio
import trio.hazmat
import rsyscall.io
import os

class TestIO(unittest.TestCase):
    def test_pipe(self):
        async def test() -> None:
            syscall = rsyscall.io.LocalSyscall(trio.hazmat.wait_readable)
            async with rsyscall.io.allocate_pipe(syscall) as (r, w):
                in_data = b"hello"
                await w.write(in_data)
                out_data = await r.read(len(in_data))
                self.assertEqual(in_data, out_data)
        trio.run(test)

    def test_subprocess(self):
        async def test() -> None:
            syscall = rsyscall.io.LocalSyscall(trio.hazmat.wait_readable)
            print("pid 1", os.getpid())
            await syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
            print("pid 2", os.getpid())
            await syscall.exit(0)
            print("pid 3", os.getpid())
        trio.run(test)

    def test_subprocess_context(self):
        async def test() -> None:
            syscall = rsyscall.io.LocalSyscall(trio.hazmat.wait_readable)
            print("pid 1", os.getpid())
            async def my_exit():
                await syscall.exit(0)
            await syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
            print("forcibly exiting process")
            await my_exit()
            # await context._get_syscall().exit(0)
            print("pid 4", os.getpid())
        trio.run(test)

    def test_subprocess_context_bak(self):
        async def test() -> None:
            syscall = rsyscall.io.LocalSyscall(trio.hazmat.wait_readable)
            print("pid 1", os.getpid())
            async with rsyscall.io.make_subprocess(syscall) as subproc:
                print("pid 2", os.getpid())
                await subproc.exit(0)
                print("pid 3", os.getpid())
            print("pid 4", os.getpid())
        trio.run(test)

    @unittest.skip("bad")
    def test_nested_subprocess(self):
        async def test() -> None:
            syscall = rsyscall.io.LocalSyscall(trio.hazmat.wait_readable)
            print("pid 1", os.getpid())
            async with rsyscall.io.make_subprocess(syscall):
                print("pid 2", os.getpid())
                async with rsyscall.io.make_subprocess(syscall) as subproc:
                    print("pid 3", os.getpid())
                    await subproc.exit(0)
                    print("pid 4", os.getpid())
                print("pid 5", os.getpid())
            print("pid 6", os.getpid())
        trio.run(test)

if __name__ == '__main__':
    import unittest
    unittest.main()


