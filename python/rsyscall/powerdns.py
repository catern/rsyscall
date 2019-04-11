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
import dns.zone

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
*.neato.com. 123 LUA NS ("; local dn = qname:makeRelative(newDN('neato.com'));"
                          "local labels = dn:getRawLabels();"
                          "local components = labels[#labels];"
                          "if tonumber(components) > (#labels - 1) then return nil end;"
                          "local nslabels = {table.unpack(labels, #labels-components, #labels-1)};"
                          "return table.concat(nslabels, '.');")
a.neato.com. 123 A 1.2.3.4
""")
    named_path = await rsc.spit(cwd/"named.conf", """
zone "neato.com" {
     type master;
     file "%s";
};
""" % (os.fsdecode(zone_path),))
    udp_sock = await thread.stdtask.task.socket_inet(socket.SOCK.DGRAM)
    await udp_sock.bind(rsc.InetAddress(53, 0x7F_00_00_02))
    tcp_sock = await thread.stdtask.task.socket_inet(socket.SOCK.STREAM)
    await tcp_sock.bind(rsc.InetAddress(53, 0x7F_00_00_02))
    await tcp_sock.listen(10)

    # addr = socket.Inet6Address(0, "::1")
    # ptr = await thread.stdtask.task.to_pointer(addr)
    # udp6_sock = await thread.stdtask.task.base.socket(socket.AF.INET6, socket.SOCK.DGRAM)
    # await udp6_sock.bind(ptr, addr.sizeof())
    # tcp6_sock = await thread.stdtask.task.base.socket(socket.AF.INET6, socket.SOCK.STREAM)
    # await tcp6_sock.bind(ptr, addr.sizeof())
    # await tcp6_sock.listen(10)

    config = {
        "config-dir": os.fsdecode(cwd),
        # TODO control-console seems to be a feature where it will listen on stdin or something?
        # we should use that instead of this socketdir
        "socket-dir": os.fsdecode(cwd),
        # more logging
        "loglevel": "9",
        "log-dns-queries": "yes",
        # backend
        "launch": "bind",
        "bind-config": os.fsdecode(named_path),
        "enable-lua-records": "yes",
        # relevant stuff
        "local-address": "127.0.0.2",
        "local-ipv6": "",
        # "local-ipv6": "::1",
        "local-address-udp-fds": "127.0.0.2=" + str(int(udp_sock.handle.near)),
        "local-address-tcp-fds": "127.0.0.2=" + str(int(tcp_sock.handle.near)),
        # "local-ipv6-udp-fds": "::1=" + str(int(udp6_sock.near)),
        # "local-ipv6-tcp-fds": "::1=" + str(int(tcp6_sock.near)),
    }
    config_args = [f"--{name}={value}" for name, value in config.items()]
    await thread.stdtask.unshare_files(going_to_exec=True)
    await udp_sock.handle.disable_cloexec()
    await tcp_sock.handle.disable_cloexec()
    # await udp6_sock.disable_cloexec()
    # await tcp6_sock.disable_cloexec()
    child = await thread.exec(
        pdns_server.args(*config_args))
    nursery.start_soon(child.check)
    return Powerdns()

def make_node(rdatasets: t.List[dns.rdataset.Rdataset]) -> dns.node.Node:
    node = dns.node.Node()
    node.rdatasets = rdatasets
    return node

async def start_recursor(nursery, stdtask: StandardTask, path: Path, root_hints: dns.zone.Zone=None) -> Powerdns:
    pdns_recursor = rsc.Command(stdtask.task.base.make_path_from_bytes(
        "/home/sbaugh/.local/src/pdns/pdns/recursordist/pdns_recursor"),
                                ['pdns_recursor'], {})
    thread = await stdtask.fork()
    await thread.stdtask.task.unshare_fs()
    await thread.stdtask.task.chdir(path)
    cwd = thread.stdtask.task.cwd()

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
        "log-common-errors": "yes",
        "quiet": "no",
        # "trace": "yes",
        "dont-query": "",
        "logging-facility": "0",
        # relevant stuff
        "local-address": "127.0.0.1",
        "allow-from": "127.0.0.0/8",
        "local-address-udp-fds": "127.0.0.1=" + str(int(udp_sock.handle.near)),
        "local-address-tcp-fds": "127.0.0.1=" + str(int(tcp_sock.handle.near)),
    }
    if root_hints is not None:
        config["hint-file"] = os.fsdecode(await rsc.spit(cwd/'root.hints', root_hints.to_text()))
    await thread.stdtask.unshare_files(going_to_exec=True)
    await udp_sock.handle.disable_cloexec()
    await tcp_sock.handle.disable_cloexec()
    child = await thread.exec(pdns_recursor.args(*[f"--{name}={value}" for name, value in config.items()]))
    nursery.start_soon(child.check)
    return Powerdns()


class TestPowerdns(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.ns_thread = await rsc.local_stdtask.fork()
        self.stdtask = self.ns_thread.stdtask
        await self.stdtask.unshare_user(0, 0)
        await self.stdtask.unshare_net()
        # set loopback up
        ip = await rsc.which(self.stdtask, "ip")
        # TODO blah this requires root and we don't want to have to run as root because it's a hassle
        # well, I guess we should be sandboxing anything bad, so maybe we should run as root..
        # no that's silly
        await self.stdtask.run(ip.args('link', 'set', 'dev', 'lo', 'up'))
        self.tmpdir = await self.stdtask.mkdtemp("test_powerdns")
        self.path = self.tmpdir.path
        self.dig = await rsc.which(self.stdtask, "dig")
        self.powerdns = await start_powerdns(self.nursery, self.stdtask, self.path)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_recursor(self) -> None:
        from dns.rdataset import from_text_list as rd
        hints = dns.zone.Zone('.', relativize=False)
        hints['.'] = make_node([
            rd('IN', 'NS', 3600000, ['A.ROOT-SERVERS.NET.'])
        ])
        hints['A.ROOT-SERVERS.NET.'] = make_node([
            rd('IN', 'A', 3600000, ['127.0.0.2'])
        ])
        self.powerdns = await start_recursor(self.nursery, self.stdtask, self.path, root_hints=hints)
        await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'A', 'a.neato.com'))

    async def test_powerdns(self) -> None:
        dig = await rsc.which(self.stdtask, "dig")
        # oh hmm we want to return an NS record for something else though
        # that's awkward to do with lua records.
        # or... maybe this is fine? can we return NS record for this domain at all levels?
        # in any case, now we have this thing working.
        # so... we can write a better test.
        await self.stdtask.run(dig.args('@localhost', '-p', '1053', 'NS', 'a.b.c.2.neato.com'))
        # await self.stdtask.run(dig.args('@localhost', '-p', '1053', 'NS', 'a.b.c.2.neato.com'))
        # await self.stdtask.run(dig.args('@localhost', '-p', '1053', 'NS', 'foo.neato.com'))
