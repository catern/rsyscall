from __future__ import annotations
import typing as t
import time
from rsyscall._raw import lib # type: ignore
from rsyscall._raw import ffi # type: ignore
import os
import abc
import trio
import rsyscall.io as rsc
import rsyscall.handle as handle
import rsyscall.near
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.io import StandardTask, RsyscallThread, Command
from rsyscall.handle import FileDescriptor, Path
from dataclasses import dataclass
from rsyscall.struct import Int32, Bytes
from rsyscall.monitor import AsyncChildProcess

import rsyscall.tasks.local as local
from rsyscall.sys.capability import CAP, CapHeader, CapData
from rsyscall.sys.socket import AF, SOCK, SOL
from rsyscall.sys.prctl import PrctlOp, CapAmbient
from rsyscall.fcntl import O
from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.netinet.ip import IP, IPPROTO
from rsyscall.linux.netlink import SockaddrNl, NETLINK
from rsyscall.linux.rtnetlink import RTMGRP
from rsyscall.handle import FDPair
import rsyscall.net.if_ as netif

import rsyscall.nix as nix

miredo_nixdep = nix.import_nix_dep("miredo")

@dataclass
class MiredoExecutables:
    run_client: Command
    privproc: Command

    @classmethod
    async def from_store(cls, store: nix.Store) -> MiredoExecutables:
        miredo_path = await store.realise(miredo_nixdep)
        return MiredoExecutables(
            run_client=Command(miredo_path.handle/"libexec"/"miredo"/"miredo-run-client", ["miredo-run-client"], {}),
            privproc=Command(miredo_path.handle/"libexec"/"miredo"/"miredo-privproc", ["miredo-privproc"], {}),
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
    ns_thread: RsyscallThread

async def exec_miredo_privproc(
        miredo_exec: MiredoExecutables,
        thread: RsyscallThread,
        privproc_side: FileDescriptor, tun_index: int) -> AsyncChildProcess:
    privproc_side = privproc_side.move(thread.stdtask.task.base)
    await thread.stdtask.unshare_files(going_to_exec=True)
    await thread.stdtask.stdin.copy_from(privproc_side)
    await thread.stdtask.stdout.replace_with(privproc_side)
    child = await thread.exec(miredo_exec.privproc.args(str(tun_index)))
    return child

async def exec_miredo_run_client(
        miredo_exec: MiredoExecutables,
        thread: RsyscallThread,
        inet_sock: FileDescriptor,
        tun_fd: FileDescriptor,
        reqsock: FileDescriptor,
        icmp6_fd: FileDescriptor,
        client_side: FileDescriptor,
        server_name: str) -> AsyncChildProcess:
    fd_args = [fd.move(thread.stdtask.task.base)
               for fd in [inet_sock, tun_fd, reqsock, icmp6_fd, client_side]]
    await thread.stdtask.unshare_files(going_to_exec=True)
    child = await thread.exec(miredo_exec.run_client.args(
        *[str(await fd.as_argument()) for fd in fd_args],
        server_name, server_name))
    return child

async def add_to_ambient(task: rsc.Task, capset: t.Set[CAP]) -> None:
    hdr_ptr = await task.to_pointer(CapHeader())
    data_ptr = await task.malloc_struct(CapData)
    await task.base.capget(hdr_ptr, data_ptr)
    data = await data_ptr.read()
    data.inheritable.update(capset)
    data_ptr = await data_ptr.write(data)
    await task.base.capset(hdr_ptr, data_ptr)
    for cap in capset:
        await task.base.prctl(PrctlOp.CAP_AMBIENT, CapAmbient.RAISE, cap)

async def start_miredo(nursery, miredo_exec: MiredoExecutables, stdtask: StandardTask) -> Miredo:
    inet_sock = await stdtask.task.base.socket(AF.INET, SOCK.DGRAM)
    await inet_sock.bind(await stdtask.task.to_pointer(SockaddrIn(0, 0)))
    # set a bunch of sockopts
    one = await stdtask.task.to_pointer(Int32(1))
    await inet_sock.setsockopt(SOL.IP, IP.RECVERR, one)
    await inet_sock.setsockopt(SOL.IP, IP.PKTINFO, one)
    await inet_sock.setsockopt(SOL.IP, IP.MULTICAST_TTL, one)
    # hello fragments my old friend
    await inet_sock.setsockopt(SOL.IP, IP.MTU_DISCOVER,
                               await stdtask.task.to_pointer(Int32(IP.PMTUDISC_DONT)))
    ns_thread = await stdtask.fork()
    await ns_thread.stdtask.unshare_user()
    await ns_thread.stdtask.unshare_net()
    # create icmp6 fd so miredo can relay pings
    icmp6_fd = await ns_thread.stdtask.task.base.socket(AF.INET6, SOCK.RAW, IPPROTO.ICMPV6)

    # create the TUN interface
    tun_fd = await ns_thread.task.base.open(await ns_thread.ram.to_pointer(Path("/dev/net/tun")), O.RDWR|O.CLOEXEC)
    ptr = await stdtask.task.to_pointer(netif.Ifreq(b'teredo', flags=netif.IFF_TUN))
    await tun_fd.ioctl(netif.TUNSETIFF, ptr)
    # create reqsock for ifreq operations in this network namespace
    reqsock = await ns_thread.stdtask.task.base.socket(AF.INET, SOCK.STREAM)
    await reqsock.ioctl(netif.SIOCGIFINDEX, ptr)
    tun_index = (await ptr.read()).ifindex
    ptr.free()
    # create socketpair for communication between privileged process and teredo client
    privproc_pair = await (await ns_thread.stdtask.task.base.socketpair(
        AF.UNIX, SOCK.STREAM, 0, await ns_thread.stdtask.task.malloc_struct(FDPair))).read()

    privproc_thread = await ns_thread.stdtask.fork()
    await add_to_ambient(privproc_thread.stdtask.task, {CAP.NET_ADMIN})
    privproc_child = await exec_miredo_privproc(miredo_exec, privproc_thread, privproc_pair.first, tun_index)
    nursery.start_soon(privproc_child.check)

    # TODO lock down the client thread, it's talking on the network and isn't audited...
    # should clear out the mount namespace
    # iterate through / and umount(MNT_DETACH) everything that isn't /nix
    # ummm and let's use UMOUNT_NOFOLLOW too
    # ummm no let's just only umount directories
    client_thread = await ns_thread.stdtask.fork(newpid=True)
    await client_thread.stdtask.unshare_net()
    await client_thread.stdtask.unshare_mount()
    await client_thread.stdtask.unshare_user()
    client_child = await exec_miredo_run_client(
        miredo_exec, client_thread, inet_sock, tun_fd, reqsock, icmp6_fd, privproc_pair.second, "teredo.remlab.net")
    nursery.start_soon(client_child.check)

    # we keep the ns thread around so we don't have to mess with setns
    return Miredo(ns_thread)

class TestMiredo(TrioTestCase):
    async def asyncSetUp(self) -> None:
        # TODO lmao stracing this stuff causes a bug,
        # what is even going on
        self.stdtask = local.stdtask
        print("a", time.time())
        self.exec = await MiredoExecutables.from_store(nix.local_store)
        print("a1", time.time())
        self.miredo = await start_miredo(self.nursery, self.exec, self.stdtask)
        print("b", time.time())
        self.netsock = await self.miredo.ns_thread.stdtask.task.base.socket(AF.NETLINK, SOCK.DGRAM, NETLINK.ROUTE)
        print("b-1", time.time())
        print("b0", time.time())
        await self.netsock.bind(
            await self.miredo.ns_thread.stdtask.task.to_pointer(SockaddrNl(0, RTMGRP.IPV6_ROUTE)))
        print("b0.5", time.time())


    async def test_miredo(self) -> None:
        print("b1", time.time())
        ping6 = (await rsc.which(self.stdtask, "ping")).args('-6')
        print("b1.5", time.time())
        # TODO lol actually parse this, don't just read and throw it away
        await self.netsock.read(await self.miredo.ns_thread.stdtask.task.malloc_type(Bytes, 4096))
        print("b2", time.time())
        thread = await self.miredo.ns_thread.stdtask.fork()
        print("c", time.time())
        # bash = await rsc.which(self.stdtask, "bash")
        # await (await thread.exec(bash)).check()
        await add_to_ambient(thread.stdtask.task, {CAP.NET_RAW})
        await (await thread.exec(ping6.args('-c', '1', 'google.com'))).check()
        print("d", time.time())

if __name__ == "__main__":
    import unittest
    unittest.main()
