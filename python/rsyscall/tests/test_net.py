from rsyscall.trio_test_case import TrioTestCase
import rsyscall.tasks.local as local
from rsyscall.path import Path
from rsyscall.fcntl import O
from rsyscall.sys.socket import AF, SOCK
from rsyscall.net.if_ import *
from rsyscall.linux.netlink import *
from rsyscall.linux.rtnetlink import *
from pyroute2 import IPBatch
from rsyscall.sched import CLONE

class TestNet(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thr = await local.thread.clone(CLONE.NEWUSER|CLONE.NEWNET)

    async def asyncTearDown(self) -> None:
        await self.thr.close()

    async def test_setns_ownership(self) -> None:
        netnsfd = await self.thr.task.open(await self.thr.ram.ptr(Path("/proc/self/ns/net")), O.RDONLY)
        thread = await self.thr.clone(CLONE.FILES)
        await thread.unshare_user()
        with self.assertRaises(PermissionError):
            # we can't setns to a namespace that we don't own, which is fairly lame
            await thread.task.setns(netnsfd, CLONE.NEWNET)

    async def test_make_tun(self) -> None:
        tun_fd = await self.thr.task.open(await self.thr.ram.ptr(Path("/dev/net/tun")), O.RDWR)
        ptr = await self.thr.ram.ptr(Ifreq(b'tun0', flags=IFF_TUN))
        await tun_fd.ioctl(TUNSETIFF, ptr)
        sock = await self.thr.task.socket(AF.INET, SOCK.STREAM)
        await sock.ioctl(SIOCGIFINDEX, ptr)
        # this is the second interface in an empty netns
        self.assertEqual((await ptr.read()).ifindex, 2)

    async def test_rtnetlink(self) -> None:
        netsock = await self.thr.task.socket(AF.NETLINK, SOCK.DGRAM, NETLINK.ROUTE)
        await netsock.bind(await self.thr.ram.ptr(SockaddrNl(0, RTMGRP.LINK)))

        tun_fd = await self.thr.task.open(await self.thr.ram.ptr(Path("/dev/net/tun")), O.RDWR)
        ptr = await self.thr.ram.ptr(Ifreq(b'tun0', flags=IFF_TUN))
        await tun_fd.ioctl(TUNSETIFF, ptr)
        sock = await self.thr.task.socket(AF.INET, SOCK.STREAM)
        await sock.ioctl(SIOCGIFINDEX, ptr)
        # this is the second interface in an empty netns
        self.assertEqual((await ptr.read()).ifindex, 2)

        valid, _ = await netsock.read(await self.thr.ram.malloc(bytes, 4096))
        batch = IPBatch()
        evs = batch.marshal.parse(await valid.read())
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]['event'], 'RTM_NEWLINK')
