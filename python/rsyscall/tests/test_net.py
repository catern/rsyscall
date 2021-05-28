from dataclasses import dataclass
from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread, FileDescriptor, Thread
from rsyscall.fcntl import O
from rsyscall.sys.socket import AF, SOCK, SO, SOL
from rsyscall.net.if_ import *
from rsyscall.netinet.ip import SockaddrIn
from rsyscall.linux.netlink import *
from rsyscall.linux.rtnetlink import *
from pyroute2 import IPBatch
from rsyscall.sched import CLONE
from rsyscall.thread import write_user_mappings
import ipaddress
import logging
import trio
logger = logging.getLogger(__name__)

@dataclass
class Tun:
    thr: Thread
    fd: FileDescriptor
    name: str
    addr: ipaddress.IPv4Address
    sock: FileDescriptor

    @classmethod
    async def make(cls, parent: Thread, addr: ipaddress.IPv4Address, peer: ipaddress.IPv4Address) -> None:
        # put each tun in a separate netns; I tried putting them in
        # the same netns, but got silent packet delivery failures.
        thr = await parent.clone(CLONE.NEWNET|CLONE.FILES)
        self = cls(
            thr,
            await thr.task.open(await thr.ptr("/dev/net/tun"), O.RDWR),
            'tun0',
            addr,
            await thr.task.socket(AF.INET, SOCK.STREAM),
        )
        await self.fd.ioctl(TUNSETIFF, await self.thr.ptr(Ifreq(self.name, flags=IFF.TUN|IFF.NO_PI)))
        # set up the tun - these ioctls don't actually affect the socket
        await self.sock.ioctl(SIOC.SIFFLAGS, await self.thr.ptr(Ifreq(self.name, flags=IFF.UP)))
        await self.sock.ioctl(SIOC.SIFADDR, await self.thr.ptr(Ifreq(self.name, addr=SockaddrIn(0, self.addr))))
        await self.sock.ioctl(SIOC.SIFDSTADDR, await self.thr.ptr(Ifreq(self.name, addr=SockaddrIn(0, peer))))
        await self.sock.bind(await self.thr.ptr(SockaddrIn(1234, self.addr)))
        return self

class TestNet(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = await local_thread.clone(CLONE.NEWUSER, automatically_write_user_mappings=False)
        await write_user_mappings(
            self.thr,
            await local_thread.task.getuid(), await local_thread.task.getgid(),
            0, 0,
        )

    async def asyncTearDown(self) -> None:
        await self.thr.exit(0)

    async def test_setns_ownership(self) -> None:
        netnsfd = await self.thr.task.open(await self.thr.ram.ptr("/proc/self/ns/net"), O.RDONLY)
        thread = await self.thr.clone(CLONE.FILES)
        await thread.unshare_user()
        with self.assertRaises(PermissionError):
            # we can't setns to a namespace that we don't own, which is fairly lame
            await thread.task.setns(netnsfd, CLONE.NEWNET)

    async def test_ioctl(self) -> None:
        await self.thr.unshare(CLONE.NEWNET)
        tun_fd = await self.thr.task.open(await self.thr.ram.ptr("/dev/net/tun"), O.RDWR)
        name = 'tun0'
        ptr = await self.thr.ram.ptr(Ifreq(name, flags=IFF.TUN))
        await tun_fd.ioctl(TUNSETIFF, ptr)
        sock = await self.thr.task.socket(AF.INET, SOCK.STREAM)
        await sock.ioctl(SIOC.GIFINDEX, ptr)
        # this is the second interface in an empty netns
        self.assertEqual((await ptr.read()).ifindex, 2)
        # set it up
        ptr = await ptr.write(Ifreq(name, flags=IFF.UP))
        await sock.ioctl(SIOC.SIFFLAGS, ptr)
        await sock.ioctl(SIOC.GIFFLAGS, ptr)
        self.assertIn(IFF.UP, (await ptr.read()).flags) # type: ignore
        # add IP address
        addr = SockaddrIn(0, '10.0.0.1')
        ptr = await ptr.write(Ifreq(name, addr=addr))
        await sock.ioctl(SIOC.SIFADDR, ptr)
        await sock.ioctl(SIOC.GIFADDR, ptr)
        self.assertEqual(addr, (await ptr.read()).addr.parse())

    async def test_rtnetlink(self) -> None:
        await self.thr.unshare(CLONE.NEWNET)
        netsock = await self.thr.task.socket(AF.NETLINK, SOCK.DGRAM, NETLINK.ROUTE)
        await netsock.bind(await self.thr.ram.ptr(SockaddrNl(0, RTMGRP.LINK)))

        tun_fd = await self.thr.task.open(await self.thr.ram.ptr("/dev/net/tun"), O.RDWR)
        ptr = await self.thr.ram.ptr(Ifreq('tun0', flags=IFF.TUN))
        await tun_fd.ioctl(TUNSETIFF, ptr)
        sock = await self.thr.task.socket(AF.INET, SOCK.STREAM)
        await sock.ioctl(SIOC.GIFINDEX, ptr)
        # this is the second interface in an empty netns
        self.assertEqual((await ptr.read()).ifindex, 2)

        valid, _ = await netsock.read(await self.thr.ram.malloc(bytes, 4096))
        batch = IPBatch()
        evs = batch.marshal.parse(await valid.read())
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['event'], 'RTM_NEWLINK')

    async def test_connected_tun(self) -> None:
        left_addr, right_addr = [ipaddress.IPv4Address(f'10.0.0.{i}') for i in [1, 2]]
        left = await Tun.make(self.thr, left_addr, right_addr)
        right = await Tun.make(self.thr, right_addr, left_addr)

        logger.info("Use socat to connect the two tuns bidirectionally")
        socat = await self.thr.environ.which('socat')
        socat_thr = await self.thr.clone()
        await socat_thr.inherit_fd(left.fd).dup2(socat_thr.stdin)
        await socat_thr.inherit_fd(right.fd).dup2(socat_thr.stdout)
        socat_proc = await socat_thr.exec(socat.args('STDIN', 'STDOUT'))

        conn, acc = left, right
        logger.info("%s will connect and %s will accept", conn, acc)
        await acc.sock.listen(1)
        logger.info("Run connect and accept in parallel; this works even though we aren't using AFDs, "
                    "because the two sockets are in separate threads.")
        async with trio.open_nursery() as nursery:
            # TODO this blocks the thread for some reason...
            # nursery.start_soon(socat_proc.check)
            @nursery.start_soon
            async def do_conn():
                await conn.sock.connect(await conn.thr.ptr(SockaddrIn(1234, acc.addr)))
            accepted_conn = await acc.sock.accept()
        await conn.sock.write(await self.thr.ptr(b'hello world'))
        await accepted_conn.read(await self.thr.malloc(bytes, 4096))
