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
    # TODO miredo doesn't properly clean up its child process, sigh
    # TODO hmm we probably want to... have our own thread be the parent of this net ns...
    # maybe? or we could just setns into it...
    # yeah setnsing into it seems better
    # ok so we'll unshare user and pid,
    # then unshare net after opening the socket
    # open hmm
    # we want this to move this to be owned by stdtask. hm.
    await thread.stdtask.unshare_files(going_to_exec=True)
    await sock.handle.disable_cloexec()
    await config_fd.handle.disable_cloexec()
    child = await thread.exec(miredo.args('-f', '-c', config_fd.handle.as_proc_path(), '-u', 'root'))
    nursery.start_soon(child.check)
    return Miredo(ns_thread)

class TestMiredo(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = rsc.local_stdtask
        self.miredo = await start_miredo(self.nursery, self.stdtask)

    async def test_miredo(self) -> None:
        ping6 = await rsc.which(self.stdtask, "ping6")
        # TODO properly wait for miredo to be up...
        await trio.sleep(.1)
        # ping needs root, so let's fork it off from the
        # miredo-ns-thread, which has root in the namespace
        thread = await self.miredo.ns_thread.stdtask.fork()
        await thread.run(ping6.args('-c', '1', 'google.com'))

if __name__ == "__main__":
    import unittest
    unittest.main()
