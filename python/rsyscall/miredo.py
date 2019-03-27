from __future__ import annotations
import os
import abc
import trio
import rsyscall.io as rsc
import rsyscall.inotify as inotify
import rsyscall.handle as handle
import rsyscall.socket as socket
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.io import StandardTask, RsyscallThread, Path, Command
from rsyscall.io import FileDescriptor, ReadableWritableFile, ChildProcess
from dataclasses import dataclass

@dataclass
class Miredo:
    netnsfd: handle.FileDescriptor
    usernsfd: handle.FileDescriptor

async def start_miredo(nursery, stdtask: StandardTask) -> Miredo:
    miredo = await rsc.which(stdtask, "miredo")
    thread = await stdtask.fork()
    sock = await thread.stdtask.task.socket_inet(socket.SOCK.DGRAM)
    await sock.bind(rsc.InetAddress(0, 0))
    # set a bunch of sockopts
    await sock.setsockopt(socket.SOL.IP, socket.IP.RECVERR, 1)
    await sock.setsockopt(socket.SOL.IP, socket.IP.PKTINFO, 1)
    await sock.setsockopt(socket.SOL.IP, socket.IP.MULTICAST_TTL, 1)
    # hello fragments my old friend
    await sock.setsockopt(socket.SOL.IP, socket.IP.MTU_DISCOVER, socket.IP.PMTUDISC_DONT)
    # hmm
    config = ""
    config += "InterfaceName teredo\n"
    config += "ServerAddress teredo.remlab.net\n"
    config += "InheritedFD " + str(sock.handle.near.number) + "\n"

    config_fd = await thread.stdtask.task.memfd_create('miredo.conf')
    await config_fd.write_all(config.encode())
    await config_fd.lseek(0, os.SEEK_SET)
    # TODO properly inherit the caps we need instead of being root
    await thread.stdtask.unshare_user(0, 0)
    await thread.stdtask.unshare_net()
    # TODO miredo doesn't properly clean up its child process, sigh
    # TODO hmm we probably want to... have our own thread be the parent of this net ns...
    # maybe? or we could just setns into it...
    # yeah setnsing into it seems better
    # ok so we'll unshare user and pid,
    # then unshare net after opening the socket
    # open hmm
    # we want this to move this to be owned by stdtask. hm.
    netnsfd = await thread.stdtask.task.open(stdtask.task.root().handle/"proc"/"self"/"ns"/"net", os.O_RDONLY)
    netnsfd = netnsfd.move(stdtask.task.base)
    usernsfd = await thread.stdtask.task.open(stdtask.task.root().handle/"proc"/"self"/"ns"/"user", os.O_RDONLY)
    usernsfd = usernsfd.move(stdtask.task.base)
    await thread.stdtask.unshare_files(going_to_exec=True)
    await sock.handle.disable_cloexec()
    await config_fd.handle.disable_cloexec()
    child = await thread.exec(miredo.args('-f', '-c', config_fd.handle.as_proc_path(), '-u', 'root'))
    nursery.start_soon(child.check)
    return Miredo(netnsfd, usernsfd)

class TestMiredo(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = rsc.local_stdtask
        self.miredo = await start_miredo(self.nursery, self.stdtask)

    async def test_miredo(self) -> None:
        ping6 = await rsc.which(self.stdtask, "ping6")
        # TODO properly wait for miredo to be up...
        await trio.sleep(.1)
        # ah we have to run this in the netns thread...
        # hmm...
        # so we need setns
        thread = await self.stdtask.fork()
        # hmm. so to setns, we need to have the correct user namespace as well.
        # or something? do we just need root?
        # if we enter another userns, can we still setns to this one?
        # 
        # hmm to setns we need to have the correct user namespace I guess?
        # why doesn't just unshare_user work?
        # I guess I have to be root in the user namespace that owns the namespace?
        # otherwise I could setns to any namespace. hm.
        # ugh this is really annoying though
        # we could use a thread instead?
        # hmm let's see
        await thread.stdtask.task.base.setns_user(self.miredo.usernsfd)
        await thread.stdtask.task.base.setns_net(self.miredo.netnsfd)
        await thread.run(ping6.args('-c', '1', 'google.com'))

if __name__ == "__main__":
    import unittest
    unittest.main()
