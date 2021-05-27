from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall import local_thread
from rsyscall.fcntl import O
from rsyscall.sys.socket import AF, SOCK
from rsyscall.net.if_ import *
from rsyscall.linux.netlink import *
from rsyscall.linux.rtnetlink import *
from pyroute2 import IPBatch
from rsyscall.sched import CLONE

class TestNet(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = await local_thread.clone(CLONE.NEWUSER|CLONE.NEWNET)

    async def asyncTearDown(self) -> None:
        await self.thr.exit(0)

    async def test_setns_ownership(self) -> None:
        netnsfd = await self.thr.task.open(await self.thr.ram.ptr("/proc/self/ns/net"), O.RDONLY)
        thread = await self.thr.clone(CLONE.FILES)
        await thread.unshare_user()
        with self.assertRaises(PermissionError):
            # we can't setns to a namespace that we don't own, which is fairly lame
            await thread.task.setns(netnsfd, CLONE.NEWNET)

    async def test_make_tun(self) -> None:
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

    async def test_rtnetlink(self) -> None:
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
