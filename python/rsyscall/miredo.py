from __future__ import annotations
import os
import abc
import trio
import rsyscall.io as rsc
import rsyscall.inotify as inotify
import rsyscall.handle as handle
import rsyscall.socket as socket
import rsyscall.network as net
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.io import StandardTask, RsyscallThread, Path, Command
from rsyscall.io import FileDescriptor, ReadableWritableFile, ChildProcess
from dataclasses import dataclass

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

async def start_miredo(nursery, stdtask: StandardTask) -> Miredo:
    miredo = await rsc.which(stdtask, "miredo")
    sock = await stdtask.task.socket_inet(socket.SOCK.DGRAM)
    await sock.bind(rsc.InetAddress(0, 0))
    # set a bunch of sockopts
    await sock.setsockopt(socket.SOL.IP, socket.IP.RECVERR, 1)
    await sock.setsockopt(socket.SOL.IP, socket.IP.PKTINFO, 1)
    await sock.setsockopt(socket.SOL.IP, socket.IP.MULTICAST_TTL, 1)
    # hello fragments my old friend
    await sock.setsockopt(socket.SOL.IP, socket.IP.MTU_DISCOVER, socket.IP.PMTUDISC_DONT)
    ns_thread = await stdtask.fork()
    # TODO properly inherit the caps we need instead of being root
    await ns_thread.stdtask.unshare_user(0, 0)
    await ns_thread.stdtask.unshare_net()
    # we'll keep the ns thread around so we don't have to mess with setns;
    # we'll fork off another thread to actually exec miredo.
    # miredo doesn't properly clean up its child processes, so run it in a pid namespace
    thread = await ns_thread.stdtask.fork(newpid=True)
    sock = sock.move(thread.stdtask.task.base)
    # hmm
    config = ""
    config += "InterfaceName teredo\n"
    config += "ServerAddress teredo.remlab.net\n"
    config += "InheritedFD " + str(sock.handle.near.number) + "\n"

    config_fd = await thread.stdtask.task.memfd_create('miredo.conf')
    await config_fd.write_all(config.encode())
    await config_fd.lseek(0, os.SEEK_SET)
    await thread.stdtask.unshare_files(going_to_exec=True)
    await sock.handle.disable_cloexec()
    await config_fd.handle.disable_cloexec()
    # so for privsep let's just run privproc and main process separately, directly
    # and put privproc in empty mount namespace and locked down, with inherited cap

    # okay so I guess we'll bind the tunnel,
    # and then create the privproc to manage it,
    # and pass those down to the minimal miredo daemon
    # ok so that's easy enough
    # and then we don't need the pid namespace
    # okay so it reloads configuration by just killing the process and restarting. lol
    # okay so we should be able to cut this down a lot
    miredo_command = miredo.args('-f', '-c', config_fd.handle.as_proc_path(), '-u', 'root')
    print("command is", miredo_command.in_shell_form())
    child = await thread.exec(miredo_command)
    # child = await thread.exec(bash)
    nursery.start_soon(child.check)
    return Miredo(ns_thread)

async def start_new_miredo(nursery, stdtask: StandardTask) -> Miredo:
    # TODO need to locate pkglibexec, hmm.
    # looking up the path doesn't work...
    # since it's not necessarily at which(miredo)/../libexec
    # ok I can do a build-time thing I guess
    # ugh miredo has no pkg-config
    # ok so I can just, um. look at the path at build time?
    miredo_run_client = None
    miredo_privproc = None
    inet_sock = await stdtask.task.socket_inet(socket.SOCK.DGRAM)
    await inet_sock.bind(rsc.InetAddress(0, 0))
    # set a bunch of sockopts
    await inet_sock.setsockopt(socket.SOL.IP, socket.IP.RECVERR, 1)
    await inet_sock.setsockopt(socket.SOL.IP, socket.IP.PKTINFO, 1)
    await inet_sock.setsockopt(socket.SOL.IP, socket.IP.MULTICAST_TTL, 1)
    # hello fragments my old friend
    await inet_sock.setsockopt(socket.SOL.IP, socket.IP.MTU_DISCOVER, socket.IP.PMTUDISC_DONT)
    ns_thread = await stdtask.fork()
    # TODO properly inherit the caps we need instead of being root
    await ns_thread.stdtask.unshare_user(0, 0)
    await ns_thread.stdtask.unshare_net()

    # create the TUN interface
    tun_fd = await (ns_thread.stdtask.task.root()/"dev"/"net"/"tun").open(os.O_RDWR)
    ptr = await stdtask.task.to_pointer(net.Ifreq(b'teredo', flags=net.IFF_TUN))
    await tun_fd.handle.ioctl(net.TUNSETIFF, ptr)
    # create reqsock for ifreq operations in this network namespace
    reqsock = await ns_thread.stdtask.task.socket_inet(socket.SOCK_STREAM)
    await ns_ifreq_sock.handle.ioctl(net.SIOCGIFINDEX, ptr)
    tun_index = (await ptr.read()).ifindex
    ptr.free()
    # create socketpair for communication between privileged process and teredo client
    privproc_side, client_side = await ns_thread.stdtask.task.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)

    # TODO inherit the caps for manipulation of networking, don't be root
    privproc_thread = await ns_thread.stdtask.fork()
    privproc_side = privproc_side.move(privproc_thread.stdtask.task.base)
    await privproc_thread.stdtask.unshare_files(going_to_exec=True)
    await privproc_thread.stdtask.stdin.replace_with(privproc_side.handle)
    await privproc_thread.stdtask.stdout.replace_with(privproc_side.handle)
    privproc_child = await privproc_thread.exec(miredo_privproc.args(str(tun_index)))
    nursery.start_soon(privproc_child.check)

    # TODO lock down the client thread, it's talking on the network and isn't audited...
    # should clear out the mount namespace
    client_thread = await ns_thread.stdtask.fork()
    inet_sock = inet_sock.move(client_thread.stdtask.task.base)
    tun_fd = tun_fd.move(client_thread.stdtask.task.base)
    reqsock = reqsock.move(client_thread.stdtask.task.base)
    client_side = client_side.move(client_thread.stdtask.task.base)
    await client_thread.stdtask.unshare_files(going_to_exec=True)
    await inet_sock.handle.disable_cloexec()
    await tun_fd.handle.disable_cloexec()
    await reqsock.handle.disable_cloexec()
    await client_side.handle.disable_cloexec()
    server_name = "teredo.remlab.net"
    client_child = await client_thread.exec(miredo_run_client.args(
        str(int(inet_sock.handle.near)), str(int(tun_fd.handle.near)),
        str(int(reqsock.handle.near)), str(int(client_side.handle.near)),
        server_name, server_name))
    nursery.start_soon(client_child.check)

    # we keep the ns thread around so we don't have to mess with setns
    return Miredo(ns_thread)

class TestMiredo(TrioTestCase):
    async def asyncSetUp(self) -> None:
        # TODO lmao stracing this stuff causes a bug,
        # waiting a long time between runs causes a bug,
        # what is even going on
        self.stdtask = rsc.local_stdtask
        self.miredo = await start_miredo(self.nursery, self.stdtask)

    async def test_miredo(self) -> None:
        ping6 = await rsc.which(self.stdtask, "ping6")
        # TODO properly wait for miredo to be up...
        # Maybe there's a way to wait for a specific interface to be up?
        # We could just wait for that?
        # Right, I can just run "ip monitor".
        # I *could* use netlink directly, but that seems like a hassle.
        # can I filter it?
        # o kaaay, so I think I can use netlink directly.
        # the manpage is extremely incomplete
        # I think it might be worth using pyroute2 rather than reimplementing the parsing stuff.
        # hopefully they are a little flexible about how they build messages
        await trio.sleep(.1)
        # ping needs root, so let's fork it off from the
        # miredo-ns-thread, which has root in the namespace
        thread = await self.miredo.ns_thread.stdtask.fork()
        # bash = await rsc.which(self.stdtask, "bash")
        # await (await thread.exec(bash)).check()
        await (await thread.exec(ping6.args('-c', '1', 'google.com'))).check()

if __name__ == "__main__":
    import unittest
    unittest.main()
