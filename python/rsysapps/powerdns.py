from __future__ import annotations
import ipaddress
import time
import os
import abc
import trio
import rsyscall.handle as handle
import rsyscall.near
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.thread import Thread
from rsyscall.command import Command
from rsyscall.handle import FileDescriptor, Path
from dataclasses import dataclass
import dns.zone
from dns.rdataset import from_text_list as make_rdset
import rsysapps.dnspython_LUA
import typing as t
dns.rdata.register_type(rsysapps.dnspython_LUA, 65402, 'LUA')

from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.sys.socket import AF, SOCK
from rsyscall.sched import CLONE

@dataclass
class Powerdns:
    pass

async def start_powerdns(nursery, parent: Thread, path: Path, zone: dns.zone.Zone,
                                  # tuple is (udpfd, listening tcpfd)
                                  ipv4_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
                                  ipv6_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
) -> Powerdns:
    pdns_server = Command(Path("/home/sbaugh/.local/src/pdns/pdns/pdns_server"), ['pdns_server'], {})
    # pdns_server = await parent.environ.which("pdns_server")
    thread = await parent.clone()

    # we pretend to pass addresses like 0.0.0.1 etc
    # we add one so we don't pass 0.0.0.0 and make powerdns think it's bound to everything
    ipv4s = {str(i+1): (udp.move(thread.task), tcp.move(thread.task))
             for i, (udp, tcp) in enumerate(ipv4_sockets)}
    ipv6s = {str(i+1): (udp.move(thread.task), tcp.move(thread.task))
             for i, (udp, tcp) in enumerate(ipv6_sockets)}
    await thread.unshare_files(going_to_exec=True)
    config = {
        "config-dir": os.fsdecode(path),
        # TODO control-console seems to be a feature where it will listen on stdin or something?
        # we should use that instead of this socketdir
        "socket-dir": os.fsdecode(path),
        # more logging
        "loglevel": "9",
        "log-dns-queries": "yes",
        # backend
        "launch": "bind",
        "bind-config": os.fsdecode(await thread.spit(path/"named.conf",
            'zone "%s" { file "%s"; };' % (
                zone.origin.to_text(),
                os.fsdecode(await thread.spit(path/"zone", zone.to_text()))))),
        "enable-lua-records": "yes",
        # relevant stuff
        "local-address": ",".join(ipv4s),
        "local-address-udp-fds": ",".join([f"{i}={await fd.as_argument()}" for i, (fd, _) in ipv4s.items()]),
        "local-address-tcp-fds": ",".join([f"{i}={await fd.as_argument()}" for i, (_, fd) in ipv4s.items()]),
        "local-ipv6": ",".join(ipv6s),
        "local-ipv6-udp-fds": ",".join([f"{i}={await fd.as_argument()}" for i, (fd, _) in ipv6s.items()]),
        "local-ipv6-tcp-fds": ",".join([f"{i}={await fd.as_argument()}" for i, (_, fd) in ipv6s.items()]),
    }
    print(config['local-address-udp-fds'])
    child = await thread.exec(pdns_server.args(*[f"--{name}={value}" for name, value in config.items()]))
    nursery.start_soon(child.check)
    return Powerdns()

async def start_recursor(nursery, parent: Thread, path: Path,
                                  ipv4_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
                                  ipv6_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
                                  root_hints: dns.zone.Zone=None) -> Powerdns:
    pdns_recursor = Command(Path("/home/sbaugh/.local/src/pdns/pdns/recursordist/pdns_recursor"), ['pdns_recursor'], {})
    thread = await parent.clone()

    ipv4s = {str(i+1): (udp.move(thread.task), tcp.move(thread.task))
             for i, (udp, tcp) in enumerate(ipv4_sockets)}
    ipv6s = {"::"+str(i+1): (udp.move(thread.task), tcp.move(thread.task))
             for i, (udp, tcp) in enumerate(ipv6_sockets)}
    addresses = {**ipv4s, **ipv6s}
    await thread.unshare_files(going_to_exec=True)
    config = {
        "config-dir": os.fsdecode(path),
        "socket-dir": os.fsdecode(path),
        # more logging
        "loglevel": "9",
        "log-common-errors": "yes",
        "quiet": "no",
        "trace": "yes",
        "dont-query": "",
        "logging-facility": "0",
        # relevant stuff
        "local-address": ",".join(addresses),
        "allow-from": "127.0.0.0/8",
        "local-address-udp-fds": ",".join([f"{i}={await fd.as_argument()}" for i, (fd, _) in addresses.items()]),
        "local-address-tcp-fds": ",".join([f"{i}={await fd.as_argument()}" for i, (_, fd) in addresses.items()]),
    }
    if root_hints is not None:
        config["hint-file"] = os.fsdecode(await thread.spit(path/'root.hints', root_hints.to_text()))
    child = await thread.exec(pdns_recursor.args(*[f"--{name}={value}" for name, value in config.items()]))
    nursery.start_soon(child.check)
    return Powerdns()

def make_node(rdatasets: t.List[dns.rdataset.Rdataset]) -> dns.node.Node:
    node = dns.node.Node()
    node.rdatasets = rdatasets
    return node

def make_zone(origin: t.Union[str, dns.name.Name],
              nodes: t.Dict[t.Union[str, dns.name.Name], dns.rdataset.Rdataset]) -> dns.zone.Zone:
    zone = dns.zone.Zone(origin)
    for name, rdatasets in nodes.items():
        zone[name] = make_node(rdatasets)
    return zone


import rsyscall.tasks.local as local
class TestPowerdns(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thread = await local.thread.clone()
        await self.thread.unshare_user(0, 0)
        await self.thread.unshare(CLONE.NEWNET)
        # set loopback up
        ip = await self.thread.environ.which("ip")
        # TODO blah this requires root and we don't want to have to run as root because it's a hassle
        # well, I guess we should be sandboxing anything bad, so maybe we should run as root..
        # no that's silly
        await self.thread.run(ip.args('link', 'set', 'dev', 'lo', 'up'))
        self.pdns_idx = 1
        self.tmpdir = await self.thread.mkdtemp("test_powerdns")
        self.path = self.tmpdir.path
        self.dig = await self.thread.environ.which("dig")
        self.host = await self.thread.environ.which("host")

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def start_authoritative(self, zone: dns.zone.Zone) -> ipaddress.IPv4Address:
        idx = self.pdns_idx
        self.pdns_idx += 1
        addr = ipaddress.IPv4Address(0x7F_00_00_00 + idx)
        sockaddr = await self.thread.ram.ptr(SockaddrIn(53, addr))
        print("sockaddr", sockaddr)
        path = await self.thread.mkdir(self.path/f"pdns{idx}")

        udp_sock = await self.thread.task.socket(AF.INET, SOCK.DGRAM)
        await udp_sock.bind(sockaddr)
        tcp_sock = await self.thread.task.socket(AF.INET, SOCK.STREAM)
        await tcp_sock.bind(sockaddr)
        await tcp_sock.listen(10)

        def add_rdata(nodename: str, typ: str, ttl: int, data: str) -> None:
            node = zone.find_node(nodename, create=True)
            typ_int = dns.rdatatype.from_text(typ)
            rdata = dns.rdata.from_text(dns.rdataclass.IN, typ_int, data)
            node.find_rdataset(dns.rdataclass.IN, typ_int, create=True).add(rdata, ttl=ttl)
        add_rdata('@', 'SOA', 3600, 'ns1 root 1 123 123 123 123')
        add_rdata('@', 'NS', 3600, 'ns1')
        add_rdata('ns1', 'A', 3600, str(addr))
        powerdns = await start_powerdns(
            self.nursery, self.thread, path, zone, [(udp_sock, tcp_sock)], [])
        return addr

    async def start_recursor(self, root_hints: dns.zone.Zone) -> ipaddress.IPv4Address:
        idx = self.pdns_idx
        self.pdns_idx += 1
        addr = ipaddress.IPv4Address(0x7F_00_00_00 + idx)
        sockaddr = await self.thread.ram.ptr(SockaddrIn(53, addr))
        path = await self.thread.mkdir(self.path/f"pdns{idx}")

        udp_sock = await self.thread.task.socket(AF.INET, SOCK.DGRAM)
        await udp_sock.bind(sockaddr)
        tcp_sock = await self.thread.task.socket(AF.INET, SOCK.STREAM)
        await tcp_sock.bind(sockaddr)
        await tcp_sock.listen(10)

        powerdns = await start_recursor(
            self.nursery, self.thread, path, [(udp_sock, tcp_sock)], [], root_hints=root_hints)
        return addr

    async def test_basic(self) -> None:
        user_addr = await self.start_authoritative(make_zone('user', {
            'a': [make_rdset('IN', 'A', 3600, ['1.3.5.7'])],
        }))
        root_addr = await self.start_authoritative(make_zone('.', {
            'user': [make_rdset('IN', 'NS', 3600, ['user.glue.neato.'])],
            'user.glue.neato': [make_rdset('IN', 'A', 3600, [str(user_addr)])],
        }))
        recursor_addr = await self.start_recursor(make_zone('.', {
            '.': [make_rdset('IN', 'NS', 3600000, ['A.ROOT-SERVERS.NET.'])],
            'a.root-servers.net': [make_rdset('IN', 'A', 3600000, [str(root_addr)])],
        }))

        # TODO should assert that the address returned is actually correct
        await self.thread.run(self.host.args('a.user', str(recursor_addr)))

    async def test_bad_ns(self) -> None:
        magic_addr = await self.start_authoritative(make_zone('.', {
            '*': [make_rdset('IN', 'NS', 3600, ['foo.bar.'])],
            # 'magical': [make_rdset('IN', 'NS', 3600, ['foo.bar.'])],
            # '*': [make_rdset('IN', 'LUA', 3600, ["NS \"; return 'foo.bar.';\""])],
        }))
        await self.thread.run(self.dig.args('@'+str(magic_addr), 'NS', 'magical'))

    async def test_powerdns(self) -> None:
        user_addr = await self.start_authoritative(make_zone('user.1.magic', {
            'a': [make_rdset('IN', 'A', 3600, ['1.3.5.7'])],
        }))
        magic_addr = await self.start_authoritative(make_zone('magic', {
            # 'a.user.1': [make_rdset('IN', 'NS', 3600, ['user.'])]
            '*': [make_rdset('IN', 'LUA', 3600, ["""NS (
"; local dn = qname:makeRelative(newDN('magic'));"
"local labels = dn:getRawLabels();"
"local components = labels[#labels];"
"if tonumber(components) > (#labels - 1) then return 'no.domain' end;"
"local nslabels = {table.unpack(labels, #labels-components, #labels-1)};"
"return table.concat(nslabels, '.');"
)"""])]
        }))
        real_user_addr = await self.start_authoritative(make_zone('user', {
            '@': [make_rdset('IN', 'A', 3600, [str(user_addr)])],
        }))
        root_addr = await self.start_authoritative(make_zone('.', {
            'magic': [make_rdset('IN', 'NS', 3600, ['magic.glue.neato.'])],
            'magic.glue.neato': [make_rdset('IN', 'A', 3600, [str(magic_addr)])],
            'user': [make_rdset('IN', 'NS', 3600, ['user.glue.neato.'])],
            'user.glue.neato': [make_rdset('IN', 'A', 3600, [str(real_user_addr)])],
        }))
        recursor_addr = await self.start_recursor(make_zone('.', {
            '.': [make_rdset('IN', 'NS', 3600000, ['A.ROOT-SERVERS.NET.'])],
            'a.root-servers.net': [make_rdset('IN', 'A', 3600000, [str(root_addr)])],
        }))

        self.host = await self.thread.environ.which("host")
        # oh hmm we want to return an NS record for something else though
        # that's awkward to do with lua records.
        # or... maybe this is fine? can we return NS record for this domain at all levels?
        # in any case, now we have this thing working.
        # so... we can write a better test.
        # await self.thread.run(dig.args('@127.0.0.2', 'NS', 'a.root-servers.net'))
        # await self.thread.run(self.dig.args('@'+str(user_addr), 'A', 'a.user.1.magic'))
        # await self.thread.run(self.dig.args('@'+str(recursor_addr), '+trace', 'NS', 'user'))
        # await self.thread.run(self.dig.args('@'+str(recursor_addr), 'A', 'a.user.1.magic'))
        await self.thread.run(self.dig.args('@'+str(magic_addr), 'NS', 'a.user.1.magic'))
        # await self.thread.run(self.dig.args('@'+str(recursor_addr), 'A', 'user'))
        # await self.thread.run(self.dig.args('@'+str(recursor_addr), 'A', 'a.user.1.magic'))
        # await self.thread.run(self.host.args('-v', '-a', 'a.user.1.magic', str(recursor_addr)))
        # await self.thread.run(self.host.args('-a', 'a.user.1.magic', str(magic_addr)))
        # raise Exception('hi')
