from __future__ import annotations

from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.epoller import *
import trio
import outcome

from rsyscall.tests.utils import do_async_things
from rsyscall.near.sysif import SyscallInterface, Syscall
from dneio import RequestQueue, reset

class DelayResultSysif(SyscallInterface):
    def __init__(self, sysif: SyscallInterface, delay_queue: RequestQueue) -> None:
        self.sysif = sysif
        self.delay_queue = delay_queue

    async def syscall(self, number: SYS, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        syscall = Syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        ret = await outcome.acapture(self.sysif.syscall, number, arg1, arg2, arg3, arg4, arg5, arg6)
        await self.delay_queue.request((syscall, ret))
        return ret.unwrap()

    async def close_interface(self) -> None:
        return await self.sysif.close_interface()

    def get_activity_fd(self) -> t.Optional[handle.FileDescriptor]:
        return self.sysif.get_activity_fd()

class TestEpoller(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread

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
        afd = await self.thr.make_afd(pipe.write)
        new_afd = afd.with_handle(pipe.write)
        await new_afd.write_all_bytes(b'foo')

    async def test_delayed_eagain(self):
        pipe = await self.thr.pipe()
        thread = await self.thr.clone()
        async_pipe_rfd = await thread.make_afd(thread.inherit_fd(pipe.read))
        # write in parent, read in child
        input_data = b'hello'
        buf_to_write = await self.thr.ptr(input_data)
        buf_to_write, _ = await pipe.write.write(buf_to_write)
        self.assertEqual(await async_pipe_rfd.read_some_bytes(), input_data)
        buf = await thread.malloc(bytes, 4096)
        # set up the EAGAIN to be delayed
        queue = RequestQueue()
        thread.task.sysif = DelayResultSysif(thread.task.sysif, queue)
        @self.nursery.start_soon
        async def race_eagain():
            # wait for EAGAIN
            (syscall, result), cb = await queue.get_one()
            self.assertIsInstance(result.error, BlockingIOError)
            print(syscall, result)
            thread.task.sysif = thread.task.sysif.sysif
            queue.close(Exception("remaining syscalls?"))
            # write data after the EAGAIN
            print('writing data after EAGAIN')
            await pipe.write.write(buf_to_write)
            # give epoll event a chance to be read - it will be available immediately
            await trio.sleep(0)
            # resume the suspended EAGAIN coroutine, which should keep running and get data
            print('resuming suspended coro')
            cb.send(None)
        valid, remaining = await async_pipe_rfd.read(buf)
