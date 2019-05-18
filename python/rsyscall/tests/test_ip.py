from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local

from rsyscall.sys.socket import *
from rsyscall.netinet.in_ import *
from rsyscall.struct import Bytes

class TestSocket(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = local.thread

    async def test_stream_listen(self) -> None:
        sockfd = await self.thr.task.socket(AF.INET, SOCK.STREAM)
        zero_addr = await self.thr.ram.to_pointer(SockaddrIn(0, '127.0.0.1'))
        await sockfd.bind(zero_addr)
        await sockfd.listen(10)

        addr = await (await (await sockfd.getsockname(await self.thr.ram.to_pointer(Sockbuf(zero_addr)))).read()).buf.read()
        real_addr = await self.thr.ram.to_pointer(addr)

        clientfd = await self.thr.task.socket(AF.INET, SOCK.STREAM)
        await clientfd.connect(real_addr)
        connfd = await sockfd.accept(SOCK.CLOEXEC)

        in_data = await self.thr.ram.to_pointer(Bytes(b"hello"))
        written, _ = await clientfd.write(in_data)
        valid, _ = await connfd.read(written)
        self.assertEqual(in_data.value, await valid.read())

    async def test_dgram_connect(self) -> None:
        sockfd = await self.thr.task.socket(AF.INET, SOCK.DGRAM)
        zero_addr = await self.thr.ram.to_pointer(SockaddrIn(0, '127.0.0.1'))
        await sockfd.bind(zero_addr)

        addr = await (await (await sockfd.getsockname(await self.thr.ram.to_pointer(Sockbuf(zero_addr)))).read()).buf.read()
        real_addr = await self.thr.ram.to_pointer(addr)

        clientfd = await self.thr.task.socket(AF.INET, SOCK.DGRAM)
        await clientfd.connect(real_addr)

        in_data = await self.thr.ram.to_pointer(Bytes(b"hello"))
        written, _ = await clientfd.write(in_data)
        valid, _ = await sockfd.read(written)
        self.assertEqual(in_data.value, await valid.read())
