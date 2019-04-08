from __future__ import annotations
import time
import os
import abc
import trio
import rsyscall.io as rsc
import rsyscall.inotify as inotify
import rsyscall.handle as handle
import rsyscall.socket as socket
import rsyscall.network as net
import rsyscall.near
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.io import StandardTask, RsyscallThread, Path, Command
from rsyscall.io import FileDescriptor, ReadableWritableFile, ChildProcess
from rsyscall.capabilities import CAP, CapHeader, CapData
from rsyscall.stat import DType
from dataclasses import dataclass

@dataclass
class Powerdns:
    pass

# so let's start powerdns
async def start_powerdns(nursery, stdtask: StandardTask, path: Path) -> Powerdns:
    pdns_server = rsc.Command(stdtask.task.base.make_path_from_bytes("/home/sbaugh/.local/src/pdns/pdns/pdns_server"),
                              ['pdns_server'], {})
    # pdns_server = await rsc.which(stdtask, "pdns_server")
    thread = await stdtask.fork()
    await thread.stdtask.task.unshare_fs()
    await thread.stdtask.task.chdir(path)
    cwd = thread.stdtask.task.cwd()
    zone_path = await rsc.spit(cwd/"zone", """
@ IN SOA foobar root.neato.com (
 1
 123
 123
 123
 123
)
foo.neato.com. 123 A 1.2.3.4
""")
    named_path = await rsc.spit(cwd/"named.conf", """
zone "neato.com" {
     type master;
     file "%s";
};
""" % (os.fsdecode(zone_path),))
    udp_sock = await thread.stdtask.task.socket_inet(socket.SOCK.DGRAM)
    await udp_sock.bind(rsc.InetAddress(1053, 0x7F_00_00_01))
    tcp_sock = await thread.stdtask.task.socket_inet(socket.SOCK.STREAM)
    await tcp_sock.bind(rsc.InetAddress(1053, 0x7F_00_00_01))
    await tcp_sock.listen(10)
    config = {
        "config-dir": os.fsdecode(cwd),
        "socket-dir": os.fsdecode(cwd),
        # more logging
        "loglevel": "9",
        "log-dns-queries": "yes",
        # backend
        "launch": "bind",
        "bind-config": os.fsdecode(named_path),
        # relevant stuff
        "local-address": "127.0.0.1,0.0.0.0",
        "local-ipv6": "",
        "local-address-udp-fds": "127.0.0.1=" + str(int(udp_sock.handle.near)),
        "local-address-tcp-fds": "127.0.0.1=" + str(int(tcp_sock.handle.near)),
    }
    config_args = [f"--{name}={value}" for name, value in config.items()]
    await thread.stdtask.unshare_files(going_to_exec=True)
    await udp_sock.handle.disable_cloexec()
    await tcp_sock.handle.disable_cloexec()
    child = await thread.exec(
        pdns_server.args(*config_args))
    nursery.start_soon(child.check)
    return Powerdns()


class TestPowerdns(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = rsc.local_stdtask
        self.tmpdir = await self.stdtask.mkdtemp("test_powerdns")
        self.path = self.tmpdir.path
        self.powerdns = await start_powerdns(self.nursery, self.stdtask, self.path)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_powerdns(self) -> None:
        dig = await rsc.which(self.stdtask, "dig")
        await trio.sleep(.1)
        await self.stdtask.run(dig.args('@localhost', '-p', '1053', 'foo.neato.com'))
