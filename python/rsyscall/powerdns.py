from __future__ import annotations
import ipaddress
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
from dns.rdataset import from_text_list as make_rdset
import rsyscall.dnspython_LUA
import typing as t
dns.rdata.register_type(rsyscall.dnspython_LUA, 65402, 'LUA')

@dataclass
class Powerdns:
    pass


# so let's start powerdns
async def start_powerdns(nursery, stdtask: StandardTask, path: Path) -> Powerdns:
    pdns_server = rsc.Command(stdtask.task.base.make_path_from_bytes("/home/sbaugh/.local/src/pdns/pdns/pdns_server"),
                              ['pdns_server'], {})
    # pdns_server = await rsc.which(stdtask, "pdns_server")
    thread = await stdtask.fork()
    root_path = await rsc.spit(path/"root", make_zone('.', {
        '@': [
            make_rdset('IN', 'SOA', 3600, ['ns1.neato. root.neato. 1 123 123 123 123']),
            make_rdset('IN', 'NS', 3600, ['ns1']),
        ],
        'neato': [
            make_rdset('IN', 'NS', 3600, ['some.glue.neato.']),
        ],
        'some.glue.neato': [
            make_rdset('IN', 'A', 3600, ['127.0.0.2']),
        ],
    }).to_text())
    zone_path = await rsc.spit(path/"zone", make_zone('neato.', {
        '@': [
            make_rdset('IN', 'SOA', 3600, ['ns1.neato. root.neato. 1 123 123 123 123']),
            make_rdset('IN', 'NS', 3600, ['ns1']),
            make_rdset('IN', 'A', 3600, ['127.0.0.2']),
        ],
        'ns1': [make_rdset('IN', 'A', 3600, ['127.0.0.2'])],
        '*': [make_rdset('IN', 'LUA', 3600, ["""NS (
"; local dn = qname:makeRelative(newDN('neato'));"
"local labels = dn:getRawLabels();"
"local components = labels[#labels];"
"if tonumber(components) > (#labels - 1) then return 'no.domain' end;"
"local nslabels = {table.unpack(labels, #labels-components, #labels-1)};"
"return table.concat(nslabels, '.');"
)"""])],
    }).to_text())
    magic_path = await rsc.spit(path/"magic", make_zone('neato.1.neato.', {
        '@': [
            make_rdset('IN', 'SOA', 3600, ['ns1.neato. root.neato. 1 123 123 123 123']),
            make_rdset('IN', 'NS', 3600, ['ns1']),
        ],
        'ns1': [make_rdset('IN', 'A', 3600, ['127.0.0.2'])],
        'a': [make_rdset('IN', 'A', 3600, ['1.3.5.7'])],
    }).to_text())
    # we should figure out a nice way to generate this
    named_path = await rsc.spit(path/"named.conf", """
zone "." { file "%s"; };
zone "neato" {
     file "%s";
};
zone "neato.1.neato" { file "%s";};
""" % (os.fsdecode(root_path), os.fsdecode(zone_path), os.fsdecode(magic_path)))
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
        "config-dir": os.fsdecode(path),
        # TODO control-console seems to be a feature where it will listen on stdin or something?
        # we should use that instead of this socketdir
        "socket-dir": os.fsdecode(path),
        # more logging
        "loglevel": "9",
        "log-dns-queries": "yes",
        # backend
        "launch": "bind",
        "bind-config": os.fsdecode(named_path),
        "enable-lua-records": "yes",
        # relevant stuff
        "local-address": "2",
        "local-ipv6": "",
        # "local-ipv6": "::1",
        "local-address-udp-fds": "2=" + str(int(udp_sock.handle.near)),
        "local-address-tcp-fds": "2=" + str(int(tcp_sock.handle.near)),
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

async def start_powerdns_lowlevel(nursery, stdtask: StandardTask, path: Path, zone: dns.zone.Zone,
                                  # tuple is (udpfd, listening tcpfd)
                                  ipv4_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
                                  ipv6_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
) -> Powerdns:
    pdns_server = rsc.Command(stdtask.task.base.make_path_from_bytes("/home/sbaugh/.local/src/pdns/pdns/pdns_server"),
                              ['pdns_server'], {})
    # pdns_server = await rsc.which(stdtask, "pdns_server")
    thread = await stdtask.fork()

    ipv4s = {str(i+1): (udp.move(thread.stdtask.task.base), tcp.move(thread.stdtask.task.base))
             for i, (udp, tcp) in enumerate(ipv4_sockets)}
    ipv6s = {str(i+1): (udp.move(thread.stdtask.task.base), tcp.move(thread.stdtask.task.base))
             for i, (udp, tcp) in enumerate(ipv6_sockets)}
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
        "bind-config": os.fsdecode(await rsc.spit(path/"named.conf",
            'zone "%s" { file "%s"; };' % (
                zone.origin.to_text(),
                os.fsdecode(await rsc.spit(path/"zone", zone.to_text()))))),
        "enable-lua-records": "yes",
        # relevant stuff
        "local-address": ",".join(ipv4s),
        "local-address-udp-fds": ",".join(f"{i}={int(fd.near)}" for i, (fd, _) in ipv4s.items()),
        "local-address-tcp-fds": ",".join(f"{i}={int(fd.near)}" for i, (_, fd) in ipv4s.items()),
        "local-ipv6": ",".join(ipv6s),
        "local-ipv6-udp-fds": ",".join(f"{i}={int(fd.near)}" for i, (fd, _) in ipv6s.items()),
        "local-ipv6-tcp-fds": ",".join(f"{i}={int(fd.near)}" for i, (_, fd) in ipv6s.items()),
    }
    await thread.stdtask.unshare_files(going_to_exec=True)
    for udp, tcp in [*ipv4s.values(), *ipv6s.values()]:
        await udp.disable_cloexec()
        await tcp.disable_cloexec()
    child = await thread.exec(pdns_server.args(*[f"--{name}={value}" for name, value in config.items()]))
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
        "trace": "yes",
        "dont-query": "",
        "logging-facility": "0",
        # relevant stuff
        "local-address": "1",
        "allow-from": "127.0.0.0/8",
        "local-address-udp-fds": "1=" + str(int(udp_sock.handle.near)),
        "local-address-tcp-fds": "1=" + str(int(tcp_sock.handle.near)),
    }
    if root_hints is not None:
        config["hint-file"] = os.fsdecode(await rsc.spit(cwd/'root.hints', root_hints.to_text()))
    await thread.stdtask.unshare_files(going_to_exec=True)
    await udp_sock.handle.disable_cloexec()
    await tcp_sock.handle.disable_cloexec()
    child = await thread.exec(pdns_recursor.args(*[f"--{name}={value}" for name, value in config.items()]))
    nursery.start_soon(child.check)
    return Powerdns()

async def start_recursor_lowlevel(nursery, stdtask: StandardTask, path: Path,
                                  ipv4_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
                                  ipv6_sockets: t.List[t.Tuple[handle.FileDescriptor, handle.FileDescriptor]],
                                  root_hints: dns.zone.Zone=None) -> Powerdns:
    pdns_recursor = rsc.Command(stdtask.task.base.make_path_from_bytes(
        "/home/sbaugh/.local/src/pdns/pdns/recursordist/pdns_recursor"),
                                ['pdns_recursor'], {})
    thread = await stdtask.fork()

    ipv4s = {str(i): (udp.move(thread.stdtask.task.base), tcp.move(thread.stdtask.task.base))
             for i, (udp, tcp) in enumerate(ipv4_sockets)}
    ipv6s = {"::"+str(i): (udp.move(thread.stdtask.task.base), tcp.move(thread.stdtask.task.base))
             for i, (udp, tcp) in enumerate(ipv6_sockets)}
    addresses = {**ipv4s, **ipv6s}
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
        "local-address-udp-fds": ",".join(f"{i}={int(fd.near)}" for i, (fd, _) in addresses.items()),
        "local-address-tcp-fds": ",".join(f"{i}={int(fd.near)}" for i, (_, fd) in addresses.items()),
    }
    if root_hints is not None:
        config["hint-file"] = os.fsdecode(await rsc.spit(path/'root.hints', root_hints.to_text()))
    await thread.stdtask.unshare_files(going_to_exec=True)
    for udp, tcp in addresses.values():
        await udp.disable_cloexec()
        await tcp.disable_cloexec()
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
        self.pdns_idx = 1
        self.tmpdir = await self.stdtask.mkdtemp("test_powerdns")
        self.path = self.tmpdir.path
        self.dig = await rsc.which(self.stdtask, "dig")
        # self.powerdns = await start_powerdns(self.nursery, self.stdtask, self.path)

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def test_recursor(self) -> None:
        self.powerdns = await start_recursor(self.nursery, self.stdtask, self.path, root_hints=make_zone('.', {
            '@': [make_rdset('IN', 'NS', 3600000, ['A.ROOT-SERVERS.NET.'])],
            'a.root-servers.net': [make_rdset('IN', 'A', 3600000, ['127.0.0.2'])],
        }))
        # await self.stdtask.run(self.dig.args('@127.0.0.2', '-p', '53', 'NS', 'a.b.c.2.neato'))
        # await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'NS', 'a.b.c.2.neato'))
        # await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'A', 'a.b.neato'))
        # await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'A', 'a.neato'))
        # await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'NS', 'neato'))
        # await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'A', 'a.neato.1.neato'))
        # await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'NS', 'ns.neato.2.magic.neato'))
        await self.stdtask.run(self.dig.args('@127.0.0.1', '-p', '1053', 'A', 'a.neato.1.neato'))
        # await self.stdtask.run(self.dig.args('@127.0.0.2', '-p', '53', 'NS', 'neato.1.neato'))
        # ok so now I need to start another authoritative server.

    async def start_authoritative(self, zone: dns.zone.Zone) -> ipaddress.IPv4Address:
        idx = self.pdns_idx
        self.pdns_idx += 1
        addr = ipaddress.IPv4Address(0x7F_00_00_00 + idx)
        sockaddr = rsc.SockaddrIn(53, addr)
        print("sockaddr", sockaddr)
        path = await (self.path/f"pdns{idx}").mkdir()

        udp_sock = await self.stdtask.task.socket_inet(socket.SOCK.DGRAM)
        await udp_sock.bind(sockaddr)
        tcp_sock = await self.stdtask.task.socket_inet(socket.SOCK.STREAM)
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
        powerdns = await start_powerdns_lowlevel(
            self.nursery, self.stdtask, path, zone, [(udp_sock.handle, tcp_sock.handle)], [])
        return addr

    async def start_recursor(self, root_hints: dns.zone.Zone) -> ipaddress.IPv4Address:
        idx = self.pdns_idx
        self.pdns_idx += 1
        addr = ipaddress.IPv4Address(0x7F_00_00_00 + idx)
        sockaddr = rsc.SockaddrIn(53, addr)
        path = await (self.path/f"pdns{idx}").mkdir()

        udp_sock = await self.stdtask.task.socket_inet(socket.SOCK.DGRAM)
        await udp_sock.bind(sockaddr)
        tcp_sock = await self.stdtask.task.socket_inet(socket.SOCK.STREAM)
        await tcp_sock.bind(sockaddr)
        await tcp_sock.listen(10)

        powerdns = await start_recursor_lowlevel(
            self.nursery, self.stdtask, path, [(udp_sock.handle, tcp_sock.handle)], [], root_hints=root_hints)
        return addr

    async def test_bad_ns(self) -> None:
        magic_addr = await self.start_authoritative(make_zone('.', {
            '*': [make_rdset('IN', 'NS', 3600, ['foo.bar.'])],
            # 'magical': [make_rdset('IN', 'NS', 3600, ['foo.bar.'])],
            # '*': [make_rdset('IN', 'LUA', 3600, ["NS \"; return 'foo.bar.';\""])],
        }))
        await self.stdtask.run(self.dig.args('@'+str(magic_addr), 'NS', 'magical'))
        raise Exception

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

        self.host = await rsc.which(self.stdtask, "host")
        # oh hmm we want to return an NS record for something else though
        # that's awkward to do with lua records.
        # or... maybe this is fine? can we return NS record for this domain at all levels?
        # in any case, now we have this thing working.
        # so... we can write a better test.
        # await self.stdtask.run(dig.args('@127.0.0.2', 'NS', 'a.root-servers.net'))
        # await self.stdtask.run(self.dig.args('@'+str(user_addr), 'A', 'a.user.1.magic'))
        # await self.stdtask.run(self.dig.args('@'+str(recursor_addr), '+trace', 'NS', 'user'))
        # await self.stdtask.run(self.dig.args('@'+str(recursor_addr), 'A', 'a.user.1.magic'))
        await self.stdtask.run(self.dig.args('@'+str(magic_addr), 'NS', 'a.user.1.magic'))
        # await self.stdtask.run(self.dig.args('@'+str(recursor_addr), 'A', 'user'))
        # await self.stdtask.run(self.dig.args('@'+str(recursor_addr), 'A', 'a.user.1.magic'))
        # await self.stdtask.run(self.host.args('-v', '-a', 'a.user.1.magic', str(recursor_addr)))
        # await self.stdtask.run(self.host.args('-a', 'a.user.1.magic', str(magic_addr)))
        # raise Exception('hi')
