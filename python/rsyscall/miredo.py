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
