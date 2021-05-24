from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread, FileDescriptor, Pointer
from rsyscall.epoller import *
import trio
import outcome

from rsyscall.tests.utils import do_async_things
from rsyscall.near.sysif import SyscallInterface, Syscall
from rsyscall.sys.syscall import SYS
from dneio import RequestQueue, reset, Continuation
import typing as t

class DelayResultSysif(SyscallInterface):
    def __init__(self, sysif: SyscallInterface,
                 delay_queue: RequestQueue[t.Tuple[Syscall, outcome.Outcome[int]], None]) -> None:
        self.sysif = sysif
        self.delay_queue = delay_queue

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        syscall = Syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        ret = await outcome.acapture(self.sysif.syscall, number, arg1, arg2, arg3, arg4, arg5, arg6)
        await self.delay_queue.request((syscall, ret))
        return ret.unwrap()

    async def close_interface(self) -> None:
        return await self.sysif.close_interface()

    def get_activity_fd(self) -> t.Optional[FileDescriptor]:
        return self.sysif.get_activity_fd()

class TestEpoller(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local_thread

    async def test_local(self) -> None:
        await do_async_things(self, self.thr.epoller, self.thr)

    async def test_multi(self) -> None:
        await do_async_things(self, self.thr.epoller, self.thr, 0)
        async with trio.open_nursery() as nursery:
            for i in range(1, 6):
                nursery.start_soon(do_async_things, self, self.thr.epoller, self.thr, i)

    async def test_thread_multi(self) -> None:
        thread = await self.thr.clone()
        await do_async_things(self, thread.epoller, thread, 0)
        async with trio.open_nursery() as nursery:
            for i in range(1, 6):
                nursery.start_soon(do_async_things, self, thread.epoller, thread, i)

    async def test_thread_root_epoller(self) -> None:
        thread = await self.thr.clone()
        epoller = await Epoller.make_root(thread.ram, thread.task)
        await do_async_things(self, epoller, thread)

    async def test_afd_with_handle(self):
        pipe = await self.thr.pipe()
        afd = await self.thr.make_afd(pipe.write, set_nonblock=True)
        new_afd = afd.with_handle(pipe.write)
        await new_afd.write_all_bytes(b'foo')

    async def test_delayed_eagain(self):
        pipe = await self.thr.pipe()
        thread = await self.thr.clone()
        async_pipe_rfd = await thread.make_afd(thread.inherit_fd(pipe.read), set_nonblock=True)
        # write in parent, read in child
        input_data = b'hello'
        buf_to_write: Pointer[bytes] = await self.thr.ptr(input_data)
        buf_to_write, _ = await pipe.write.write(buf_to_write)
        self.assertEqual(await async_pipe_rfd.read_some_bytes(), input_data)
        buf = await thread.malloc(bytes, 4096)
        # set up the EAGAIN to be delayed
        queue: RequestQueue[t.Tuple[Syscall, outcome.Outcome[int]], None] = RequestQueue()
        old_sysif = thread.task.sysif
        thread.task.sysif = DelayResultSysif(old_sysif, queue)
        @self.nursery.start_soon
        async def race_eagain():
            # wait for EAGAIN
            (syscall, result), cb = await queue.get_one()
            self.assertIsInstance(result.error, BlockingIOError)
            thread.task.sysif = old_sysif
            queue.close(Exception("remaining syscalls?"))
            # write data after the EAGAIN
            await pipe.write.write(buf_to_write)
            # give epoll event a chance to be read - it will be available immediately
            await trio.sleep(0)
            # resume the suspended EAGAIN coroutine, which should keep running and get data
            cb.send(None)
        valid, remaining = await async_pipe_rfd.read(buf)

    async def test_wrong_op_on_pipe(self):
        "Reading or writing to the wrong side of a pipe fails immediately with an error"
        pipe = await self.thr.pipe()
        async_pipe_wfd = await self.thr.make_afd(pipe.write, set_nonblock=True)
        async_pipe_rfd = await self.thr.make_afd(pipe.read, set_nonblock=True)
        # we actually are defined to get EBADF in this case, which is
        # a bit of a worrying error, but whatever
        with self.assertRaises(OSError) as cm:
            await async_pipe_wfd.read_some_bytes()
        self.assertEqual(cm.exception.errno, 9)
        with self.assertRaises(OSError) as cm:
            await async_pipe_rfd.write_all_bytes(b'hi')
        self.assertEqual(cm.exception.errno, 9)
