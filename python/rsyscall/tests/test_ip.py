from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.sys.socket import *
from rsyscall.netinet.in_ import *
from rsyscall import Process, Pointer, FileDescriptor
import trio
import unittest

class TestIP(TrioTestCase):
    async def test_stream_listen(self) -> None:
        sockfd = await self.process.task.socket(AF.INET, SOCK.STREAM)
        addr = await self.process.bind_getsockname(sockfd, SockaddrIn(0, '127.0.0.1'))
        await sockfd.listen(10)

        real_addr = await self.process.ram.ptr(addr)
        clientfd = await self.process.task.socket(AF.INET, SOCK.STREAM)
        await clientfd.connect(real_addr)
        connfd = await sockfd.accept()

        in_data = await self.process.ram.ptr(b"hello")
        written, _ = await clientfd.write(in_data)
        valid, _ = await connfd.read(written)
        self.assertEqual(in_data.value, await valid.read())

    async def test_dgram_connect(self) -> None:
        sockfd = await self.process.task.socket(AF.INET, SOCK.DGRAM)
        addr = await self.process.bind_getsockname(sockfd, SockaddrIn(0, '127.0.0.1'))

        real_addr = await self.process.ram.ptr(addr)
        clientfd = await self.process.task.socket(AF.INET, SOCK.DGRAM)
        await clientfd.connect(real_addr)

        in_data = await self.process.ram.ptr(b"hello")
        written, _ = await clientfd.write(in_data)
        valid, _ = await sockfd.read(written)
        self.assertEqual(in_data.value, await valid.read())

    async def test_write_to_unconnected(self) -> None:
        sockfd = await self.process.task.socket(AF.INET, SOCK.STREAM)
        with self.assertRaises(BrokenPipeError):
            await sockfd.write(await self.process.ram.ptr(b"hello"))

    @unittest.skip("This test is slow and non-deterministic")
    async def test_send_is_not_atomic(self) -> None:
        """send does, in fact, do partial writes, at least when set to NONBLOCK

        That is to say, it won't return anything less than sending the whole pointer, or (in the
        case of NONBLOCK) sending none of the pointer. This is supported by the manpage, which says:
        "When the message does not fit into the send buffer of the socket, send() normally blocks".

        Unfortunately, it's still not atomic. If multiple processes are sending at once, the data can
        be interleaved.

        """
        sockfd = await self.process.task.socket(AF.INET, SOCK.STREAM)
        addr = await self.process.bind_getsockname(sockfd, SockaddrIn(0, '127.0.0.1'))
        await sockfd.listen(10)

        real_addr = await self.process.ram.ptr(addr)
        clientfd = await self.process.task.socket(AF.INET, SOCK.STREAM)
        await clientfd.connect(real_addr)
        connfd = await sockfd.accept()
        orig_in_fd = clientfd
        orig_out_fd = connfd
        data = "".join(str(i) for i in range(8000)).encode()

        count = 100
        processes = [await self.process.fork() for _ in range(10)]
        in_ptrs = [await thr.ptr(data) for thr in processes]
        handles = [thr.task.inherit_fd(orig_in_fd) for thr in processes]
        async def run_send(process: Process, in_ptr: Pointer, fd: FileDescriptor) -> None:
            for i in range(count):
                in_ptr, rest = await fd.write(in_ptr)
                if rest.size() != 0:
                    print("failure! rest.size() is", rest.size())
                self.assertEqual(rest.size(), 0)
        read_process = await self.process.fork()
        out_buf = await read_process.malloc(bytes, len(data))
        out_fd = read_process.inherit_fd(orig_out_fd)

        had_interleaving = False
        async with trio.open_nursery() as nursery:
            for process, in_ptr, fd in zip(processes, in_ptrs, handles):
                nursery.start_soon(run_send, process, in_ptr, fd)
            for i in range(len(processes) * count):
                out_buf, rest = await out_fd.recv(out_buf, MSG.WAITALL)
                self.assertEqual(rest.size(), 0)
                if not had_interleaving:
                    indata = await out_buf.read()
                    if indata != data:
                        # oops, looks like the data from multiple processes was interleaved
                        had_interleaving = True
        for process in processes:
            await process.exit(0)
        await read_process.exit(0)
        self.assertTrue(had_interleaving)
