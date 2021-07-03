from __future__ import annotations
import typing as t
import time
from rsyscall._raw import lib # type: ignore
from rsyscall._raw import ffi # type: ignore
import os
import abc
import trio
import rsyscall.handle as handle
import rsyscall.near
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.thread import Thread, ChildThread
from rsyscall.command import Command
from rsyscall.handle import FileDescriptor, Path
from dataclasses import dataclass
from rsyscall.struct import Int32
from rsyscall.monitor import AsyncChildProcess

import rsyscall.tasks.local as local
from rsyscall.sys.capability import CAP, CapHeader, CapData
from rsyscall.sys.socket import AF, SOCK, SOL, Socketpair
from rsyscall.sys.prctl import PR, PR_CAP_AMBIENT
from rsyscall.fcntl import O
from rsyscall.sched import CLONE
from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.netinet.ip import IP, IPPROTO
from rsyscall.linux.netlink import SockaddrNl, NETLINK
from rsyscall.linux.rtnetlink import RTMGRP
from rsyscall.net.if_ import Ifreq, IFF, TUNSETIFF, SIOC

import rsyscall.nix as nix

from rsyscall._nixdeps.miredo import closure as miredo_nixdep

@dataclass
class MiredoExecutables:
    run_client: Command
    privproc: Command

    @classmethod
    async def from_store(cls, store: nix.Store) -> MiredoExecutables:
        miredo_path = await store.realise(miredo_nixdep)
        return MiredoExecutables(
            run_client=Command(miredo_path/"libexec"/"miredo"/"miredo-run-client", ["miredo-run-client"], {}),
            privproc=Command(miredo_path/"libexec"/"miredo"/"miredo-privproc", ["miredo-privproc"], {}),
        )

@dataclass
class Miredo:
    # we could use setns instead of keeping a thread around inside the namespace.
    # that would certainly be more lightweight.
    # but, the hassle with setns is that it seems you must setns to
    # the owning userns before you can setns to the netns.
    # you can't just do an unshare(USER) to get caps then setns to wherever.
    # I don't get why this is the case, and I'm not sure it can't be worked around.
    # So, I'll just use a thread, which I do understand.
    # Hopefully we can get a more lightweight setns-based approach later?
    ns_thread: ChildThread
    privproc_child: AsyncChildProcess
    client_child: AsyncChildProcess

async def add_to_ambient_caps(thr: Thread, capset: t.Set[CAP]) -> None:
    hdr = await thr.ptr(CapHeader())
    data_ptr = await thr.task.capget(hdr_ptr, await thr.malloc(CapData))
    data = await data_ptr.read()
    data.inheritable.update(capset)
    await thr.task.capset(hdr_ptr, await data_ptr.write(data))
    for cap in capset:
        await thr.task.prctl(PR.CAP_AMBIENT, PR_CAP_AMBIENT.RAISE, cap)

async def set_miredo_sockopts(thread: Thread, fd: FileDescriptor) -> None:
    # set a bunch of sockopts
    one = await thread.ram.ptr(Int32(1))
    await fd.setsockopt(SOL.IP, IP.RECVERR, one)
    await fd.setsockopt(SOL.IP, IP.PKTINFO, one)
    await fd.setsockopt(SOL.IP, IP.MULTICAST_TTL, one)
    # hello fragments my old friend
    await fd.setsockopt(SOL.IP, IP.MTU_DISCOVER, await thread.ram.ptr(Int32(IP.PMTUDISC_DONT)))

async def make_tun(thread: Thread, name: str, reqsock: FileDescriptor) -> t.Tuple[FileDescriptor, int]:
    # open /dev/net/tun
    tun_fd = await thread.task.open(await thread.ptr(Path("/dev/net/tun")), O.RDWR)
    # register TUN interface name for this /dev/net/tun fd
    ifreq = await thread.ptr(Ifreq(name, flags=IFF.TUN))
    await tun_fd.ioctl(TUNSETIFF, ifreq)
    # use reqsock to look up the interface index of the TUN interface by name (reusing the previous Ifreq)
    await reqsock.ioctl(SIOC.GIFINDEX, ifreq)
    tun_index = (await ifreq.read()).ifindex
    return tun_fd, tun_index

async def unmount_everything_except(thread: Thread, path: Path) -> None:
    pass

async def start_miredo_internal(thread: Thread, miredo_exec: MiredoExecutables) -> Miredo:
    ### create socket outside network namespace that Miredo will use for internet access
    inet_sock = await thread.socket(AF.INET, SOCK.DGRAM)
    await inet_sock.bind(await thread.ptr(SockaddrIn(0, 0)))
    # set some miscellaneous additional sockopts that Miredo wants
    await set_miredo_sockopts(thread, inet_sock)
    ### create main network namespace thread
    ns_thread = await thread.clone(CLONE.NEWNET|CLONE.NEWUSER)
    ### create in-network-namespace raw INET6 socket which Miredo will use to relay pings
    icmp6_fd = await ns_thread.socket(AF.INET6, SOCK.RAW, IPPROTO.ICMPV6)
    ### create in-network-namespace socket which Miredo will use for unassociated Ifreq ioctls
    reqsock = await ns_thread.socket(AF.INET, SOCK.STREAM)
    ### create and set up the TUN interface
    tun_fd, tun_index = await make_tun(ns_thread, "miredo", reqsock)
    ### create socketpair which Miredo will use to communicate between privileged process and Teredo client
    privproc_pair = await ns_thread.socketpair(AF.UNIX, SOCK.STREAM)
    ### start up privileged process which manipulates the network setup in the namespace
    # privproc_thread is cloned from ns_thread, which was also created through clone; this nesting is fully supported
    privproc_thread = await ns_thread.clone()
    # preserve NET_ADMIN capability over exec so that privproc can manipulate the TUN interface
    # helper function used because manipulating Linux ambient capabilities is fairly verbose
    await add_to_ambient_caps(privproc_thread, {CAP.NET_ADMIN})
    # privproc expects to communicate with the main client over stdin and stdout
    privproc_side = privproc_thread.inherit_fd(privproc_pair.first)
    await privproc_side.dup2(privproc_thread.stdin)
    await privproc_side.dup2(privproc_thread.stdout)
    privproc_child = await privproc_thread.execve(miredo_exec.privproc.executable_path, [
        miredo_exec.privproc.executable_path, str(tun_index)
    ])
    ### start up Miredo client process which communicates over the internet to implement the tunnel
    # the client process doesn't need to be in the same network namespace, since it is passed all
    # the resources it needs as fds at startup.
    client_thread = await ns_thread.clone(CLONE.NEWUSER|CLONE.NEWNET|CLONE.NEWNS|CLONE.NEWPID)
    # lightly sandbox by unmounting everything except for the executable and its deps (known via package manager)
    await unmount_everything_except(client_thread, miredo_exec.run_client.executable_path)
    # a helper function
    async def pass_fd(fd: FileDescriptor) -> str:
        await client_thread.inherit_fd(fd).disable_cloexec()
        return str(int(fd))
    client_child = await client_thread.execve(miredo_exec.run_client.executable_path, [
        miredo_exec.run_client.executable_path,
        await pass_fd(inet_sock), await pass_fd(tun_fd), await pass_fd(reqsock),
        await pass_fd(icmp6_fd), await pass_fd(privproc_pair.second),
        "teredo.remlab.net", "teredo.remlab.net"
    ])
    return Miredo(ns_thread, client_child, privproc_child)

async def start_miredo(nursery, miredo_exec: MiredoExecutables, thread: Thread) -> Miredo:
    miredo = await start_miredo_internal(thread, miredo_exec)
    nursery.start_soon(miredo.privproc_child.check)
    nursery.start_soon(miredo.client_child.check)
    return miredo

class TestMiredo(TrioTestCase):
    async def asyncSetUp(self) -> None:
        # TODO lmao stracing this stuff causes a bug,
        # what is even going on
        self.thread = local.thread
        print("a", time.time())
        self.exec = await MiredoExecutables.from_store(nix.local_store)
        print("a1", time.time())
        self.miredo = await start_miredo(self.nursery, self.exec, self.thread)
        print("b", time.time())
        self.netsock = await self.miredo.ns_thread.task.socket(AF.NETLINK, SOCK.DGRAM, NETLINK.ROUTE)
        print("b-1", time.time())
        print("b0", time.time())
        await self.netsock.bind(
            await self.miredo.ns_thread.ram.ptr(SockaddrNl(0, RTMGRP.IPV6_ROUTE)))
        print("b0.5", time.time())


    async def test_miredo(self) -> None:
        print("b1", time.time())
        ping6 = (await self.thread.environ.which("ping")).args('-6')
        print("b1.5", time.time())
        # TODO lol actually parse this, don't just read and throw it away
        await self.netsock.read(await self.miredo.ns_thread.ram.malloc(bytes, 4096))
        print("b2", time.time())
        thread = await self.miredo.ns_thread.clone()
        print("c", time.time())
        # bash = await rsc.which(self.thread, "bash")
        # await (await thread.exec(bash)).check()
        await add_to_ambient_caps(thread, {CAP.NET_RAW})
        await (await thread.exec(ping6.args('-c', '1', 'google.com'))).check()
        print("d", time.time())

if __name__ == "__main__":
    import unittest
    unittest.main()
