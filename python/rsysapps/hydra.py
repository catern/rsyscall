from __future__ import annotations
import abc
import json
import email
import h11
import socket
import time
import os
import trio
import typing as t
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.thread import Thread, ChildThread
from rsyscall.handle import FileDescriptor, Path, WrittenPointer, Pointer
from rsyscall.command import Command
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess
from dataclasses import dataclass
import rsyscall.tasks.local as local
from rsyscall.mktemp import update_symlink
from rsyscall.nix import local_store
from rsyscall.tasks.stub import StubServer

from rsyscall.inotify_watch import Inotify

from rsyscall.sched import CLONE
from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.sys.inotify import IN
from rsyscall.sys.socket import AF, SOCK, Sockbuf
from rsyscall.fcntl import O
from rsyscall.sys.un import SockaddrUn

class JobsetInput:
    @abc.abstractmethod
    def type(self) -> str: ...
    @abc.abstractmethod
    def value(self) -> str: ...
    def dict(self) -> t.Dict[str, str]:
        return {"type": self.type(), "value": self.value()}

class JobsetIncludeInput(JobsetInput):
    """"

    The subset of jobset inputs which get put on the Nix include path,
    and therefore are valid candidates for finding the jobset input
    expression.

    """    
    pass

@dataclass
class PathInput(JobsetIncludeInput):
    path: Path
    def type(self) -> str:
        return "path"
    def value(self) -> str:
        return os.fsdecode(self.path)

@dataclass
class StringInput(JobsetInput):
    string: str
    def type(self) -> str:
        return "string"
    def value(self) -> str:
        return self.string

def lookup_alist(alist: t.List[t.Tuple[bytes, bytes]], find_key: bytes) -> t.Optional[bytes]:
    for key, value in alist:
        if key == find_key:
            return value
    return None

class HTTPClient:
    """Should an HTTP client object be called HTTPServer or HTTPClient?

    It represents a server locally - so perhaps it should be server.

    But most people call it client - so perhaps it should be client.

    I'll conform with the masses...

    """
    def __init__(self, read: t.Callable[[], t.Awaitable[bytes]],
                 write: t.Callable[[bytes], t.Awaitable[None]],
                 headers: t.List[t.Tuple[str, str]]) -> None:
        self.read = read
        self.write = write
        self.headers = headers
        self.connection = h11.Connection(our_role=h11.CLIENT)
        self.cookie: t.Optional[bytes] = None

    @staticmethod
    async def connect_unix(thread: Thread, addr: WrittenPointer[SockaddrUn]) -> HTTPClient:
        sock = await thread.make_afd(await thread.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        await sock.connect(addr)
        return HTTPClient(sock.read_some_bytes, sock.write_all_bytes, [
            ("Host", "localhost"),
            ("Accept", "application/json"),
            ("Content-Type", "application/json"),
        ])

    @staticmethod
    async def connect_inet(thread: Thread, addr: SockaddrIn) -> HTTPClient:
        sock = await thread.make_afd(await thread.socket(AF.INET, SOCK.STREAM|SOCK.NONBLOCK))
        await sock.connect(await thread.ram.ptr(addr))
        return HTTPClient(sock.read_some_bytes, sock.write_all_bytes, [
            ("Host", "localhost"),
            ("Accept", "application/json"),
            ("Content-Type", "application/json"),
        ])

    async def next_event(self) -> t.Any:
        while True:
            event = self.connection.next_event()
            if event is h11.NEED_DATA:
                data = await self.read()
                self.connection.receive_data(data)
                continue
            return event

    def get_headers(self) -> t.List[t.Tuple[str, str]]:
        if self.cookie is None:
            return self.headers
        else:
            return [*self.headers, ("Cookie", self.cookie.decode())]

    async def post(self, target: str, body: bytes) -> bytes:
        # send request
        data = self.connection.send(h11.Request(
            method="POST", target=target,
            headers=[*self.get_headers(), ("Content-Length", str(len(body)))]))
        data += self.connection.send(h11.Data(data=body))
        data += self.connection.send(h11.EndOfMessage())
        await self.write(data)
        # get response
        response = await self.next_event()
        data     = await self.next_event()
        eom      = await self.next_event()
        print(response); print(data); print(eom)
        set_cookie = lookup_alist(response.headers, b"set-cookie")
        if set_cookie is not None:
            self.cookie = set_cookie
        if response.status_code >= 300:
            raise Exception("error posting", data.data)
        self.connection.start_next_cycle()
        return data.data

    async def put(self, target: str, body: bytes) -> bytes:
        request = h11.Request(
            method="PUT", target=target,
            headers=[*self.get_headers(), ("Content-Length", str(len(body)))])
        print("PUT request", request)
        data = self.connection.send(request)
        data += self.connection.send(h11.Data(data=body))
        data += self.connection.send(h11.EndOfMessage())
        await self.write(data)
        response = await self.next_event()
        data     = await self.next_event()
        eom      = await self.next_event()
        print(response, data, eom)
        if response.status_code >= 300:
            raise Exception("error posting", data.data)
        self.connection.start_next_cycle()
        return data.data

    async def get(self, target: str) -> bytes:
        request = h11.Request(method="GET", target=target, headers=self.get_headers())
        print("request", request)
        data = self.connection.send(request)
        data += self.connection.send(h11.EndOfMessage())
        await self.write(data)
        response = await self.next_event()
        data = await self.next_event()
        eom = await self.next_event()
        print(response, data, eom)
        if response.status_code >= 300:
            raise Exception("error getting", data.data)
        self.connection.start_next_cycle()
        return data.data
        

@dataclass
class Postgres:
    sockdir: Path
    thread: Thread
    createuser_cmd: Command
    createdb_cmd: Command

    async def createuser(self, name: str) -> None:
        await self.thread.run(self.createuser_cmd.args("--host", self.sockdir, "--no-password", name))

    async def createdb(self, name: str, owner: str) -> None:
        await self.thread.run(self.createdb_cmd.args("--host", self.sockdir, "--owner", owner, name))

async def read_completely(ram: RAM, fd: FileDescriptor) -> bytes:
    data = b''
    while True:
        buf = await ram.malloc(bytes, 4096)
        valid, rest = await fd.pread(buf, offset=len(data))
        if valid.size() == 0:
            return data
        data += await valid.read()

async def start_postgres(nursery, thread: Thread, path: Path) -> Postgres:
    initdb = await thread.environ.which("initdb")
    postgres = await thread.environ.which("postgres")
    createuser = await thread.environ.which("createuser")
    createdb = await thread.environ.which("createdb")

    data = path/"data"
    await thread.run(initdb.args("--pgdata", data, "--nosync", "--no-locale", "--auth=trust"))
    sockdir = path/"sock"
    await thread.mkdir(sockdir)
    config = {
        # connection
        "listen_addresses": "''",
        "unix_socket_directories": f"'{os.fsdecode(sockdir)}'",
        # performance
        "fsync": "off",
        "synchronous_commit": "off",
        "full_page_writes": "off",
    }
    await thread.spit(data/"postgresql.auto.conf", "\n".join([f"{key} = {value}" for key, value in config.items()]))
    inty = await Inotify.make(thread)
    watch = await inty.add(data, IN.CLOSE_WRITE)

    await nursery.start(thread.run, postgres.args('-D', data))
    # pg_ctl uses the pid file to determine when postgres is up, so we do the same.
    pid_file_name = "postmaster.pid"
    pid_file = None
    name = await thread.ram.ptr(data/pid_file_name)
    while True:
        await watch.wait_until_event(IN.CLOSE_WRITE, pid_file_name)
        if pid_file is None:
            pid_file = await thread.task.open(name, O.RDONLY)
        pid_file_data = await read_completely(thread.ram, pid_file)
        try:
            # the postmaster status is on line 7
            # would be nice to get that from LOCK_FILE_LINE_PM_STATUS in pidfile.h
            pm_status = pid_file_data.split(b'\n')[7]
        except IndexError:
            pm_status = b""
        if b"ready" in pm_status:
            break
    await inty.close()
    return Postgres(sockdir, thread, createuser, createdb)

class NginxChild:
    # can support methods for reloading configuration, etc
    def __init__(self, child: AsyncChildProcess) -> None:
        self.child = child

async def exec_nginx(thread: ChildThread, nginx: Command,
                     path: Path, config: FileDescriptor,
                     listen_fds: t.List[FileDescriptor]) -> AsyncChildProcess:
    nginx_fds = [fd.maybe_copy(thread.task) for fd in listen_fds]
    config_fd = config.maybe_copy(thread.task)
    await thread.unshare_files()
    if nginx_fds:
        nginx_var = ";".join([str(await fd.as_argument()) for fd in nginx_fds]) + ';'
    else:
        nginx_var = ""
    await thread.mkdir(path/"logs")
    child = await thread.exec(
        nginx.env(NGINX=nginx_var).args("-p", path, "-c", f"/proc/self/fd/{await config_fd.as_argument()}"))
    return child

async def start_fresh_nginx(
        nursery, parent: Thread, path: Path, proxy_addr: SockaddrUn
) -> t.Tuple[SockaddrIn, NginxChild]:
    nginx = await parent.environ.which("nginx")
    thread = await parent.clone(CLONE.NEWUSER|CLONE.NEWPID)
    sock = await thread.task.socket(AF.INET, SOCK.STREAM)
    zero_addr = await thread.ram.ptr(SockaddrIn(0, 0x7F_00_00_01))
    await sock.bind(zero_addr)
    addr = await (await (await sock.getsockname(
        await thread.ram.ptr(Sockbuf(zero_addr)))).read()).buf.read()
    config = b"""
error_log stderr error;
daemon off;
events {}
http {
  access_log /proc/self/fd/1 combined;
  server {
    listen localhost:%d;
    location / {
        proxy_pass http://unix:%s;
    }
  }
}
""" % (addr.port, proxy_addr.path)
    await sock.listen(10)
    config_fd = await thread.task.open(await thread.ram.ptr(path/"nginx.conf"),
                                       O.RDWR|O.CREAT)
    remaining: Pointer = await thread.ram.ptr(config)
    while remaining.size() > 0:
        _, remaining = await config_fd.write(remaining)
    child = await exec_nginx(thread, nginx, path, config_fd, [sock])
    nursery.start_soon(child.check)
    return addr, NginxChild(child)

async def start_simple_nginx(nursery, parent: Thread, path: Path, sockpath: Path) -> NginxChild:
    nginx = await parent.environ.which("nginx")
    thread = await parent.clone(CLONE.NEWUSER|CLONE.NEWPID)
    config = b"""
error_log stderr error;
daemon off;
events {}
http {
  access_log /proc/self/fd/1 combined;
  server {
    listen localhost:3000;
    location / {
        proxy_pass http://unix:%s;
    }
  }
}
""" % os.fsencode(sockpath)
    sock = await thread.task.socket(AF.INET, SOCK.STREAM)
    await sock.bind(await thread.ram.ptr(SockaddrIn(3000, 0x7F_00_00_01)))
    await sock.listen(10)
    config_fd = await thread.task.open(await thread.ram.ptr(path/"nginx.conf"),
                                       O.RDWR|O.CREAT)
    remaining: Pointer = await thread.ram.ptr(config)
    while remaining.size() > 0:
        _, remaining = await config_fd.write(remaining)
    child = await exec_nginx(thread, nginx, path, config_fd, [sock])
    nursery.start_soon(child.check)
    return NginxChild(child)

@dataclass
class Hydra:
    addr: WrittenPointer[SockaddrUn]

class Store:
    @abc.abstractmethod
    def uri(self) -> str: ...

def build_url(root: str, **params: t.Optional[Path]) -> str:
    result = root
    first = True
    for key, value in params.items():
        if value is None:
            continue
        elif isinstance(value, Path):
            string = os.fsdecode(value)
        else:
            string = value
        if first:
            result += f"?{key}={string}"
            first = False
        else:
            result += f"&{key}={string}"
    return result

class LocalStore(Store):
    # Hydra requires the state dir to exist in the local filesystem so it can make gc roots
    # TODO let's robustify our handling of all this
    # hmmmmmm
    # so Hydra seems hardcoded to store logs in a subdirectory of hydraData.
    # actually, how does it even use this logDir?
    # okay, so... it streams the logs over to the central hydra host.
    # why not directly upload them?
    # why not just have the store on that host upload them... hmm....
    # so I see, we upload the dependencies to the host, do the build, then
    # pull the build results back I guess
    # ok so it's just that it wants to create gc roots
    # h m m
    @abc.abstractmethod
    def state_dir(self) -> Path: ...

@dataclass
class DirectStore(LocalStore):
    store: t.Optional[Path] = None
    state: t.Optional[Path] = None

    def state_dir(self) -> Path:
        if self.state is None:
            raise Exception("hmm")
        else:
            return self.state

    def uri(self) -> str:
        return build_url("local", store=self.store, state=self.state)

@dataclass
class DaemonStore(Store):
    def uri(self) -> str:
        return "daemon"

async def start_hydra(nursery, thread: Thread, path: Path, dbi: str, store: LocalStore) -> Hydra:
    # maybe have a version of this function which uses cached path locations?
    # or better yet, compiled in locations?
    hydra_init = await thread.environ.which("hydra-init")
    hydra_create_user = await thread.environ.which("hydra-create-user")
    hydra_server = await thread.environ.which("hydra-server")
    hydra_evaluator = await thread.environ.which("hydra-evaluator")
    hydra_queue_runner = await thread.environ.which("hydra-queue-runner")

    await thread.run(hydra_init.env(HYDRA_DBI=dbi, HYDRA_DATA=path))
    await thread.run(hydra_create_user.args(
        "sbaugh",
        "--full-name", "Spencer Baugh",
        "--email-address", "sbaugh@localhost",
        "--password", "foobar",
        "--role", "admin",
    ).env(HYDRA_DBI=dbi, HYDRA_DATA=path))

    # create config files
    config = {"email_notification": "1"}
    config_path = await thread.spit(path/"hydra.conf", "\n".join([f"{key} = {value}" for key, value in config.items()]))
    hydra_env: t.Mapping[str, t.Union[str, bytes, os.PathLike]] = {
        'HYDRA_DBI': dbi,
        'HYDRA_DATA': path,
        'HYDRA_CONFIG': config_path,
        'NIX_REMOTE': store.uri(),
        'NIX_STATE_DIR': store.state_dir(),
    }
    # start server
    server_thread = await thread.clone()
    await server_thread.unshare_files()
    sock = await server_thread.task.socket(AF.UNIX, SOCK.STREAM)
    addr = await server_thread.ram.ptr(
        await SockaddrUn.from_path(server_thread, path/"hydra_server.sock"))
    await sock.bind(addr)
    await sock.listen(10)
    ssport = os.fsdecode(addr.value.path)+"="+str(int(sock.near))
    server_child = await server_thread.exec(hydra_server.env(
        **hydra_env, SERVER_STARTER_PORT=ssport))
    nursery.start_soon(server_child.check)
    # start evaluator, queue runner
    await nursery.start(thread.run, hydra_evaluator.env(**hydra_env))
    await nursery.start(thread.run, hydra_queue_runner.env(**hydra_env))
    return Hydra(addr)

class Jobset:
    def __init__(self, project: Project, identifier: str) -> None:
        self.project = project
        self.identifier = identifier

class Project:
    def __init__(self, client: HydraClient, identifier: str) -> None:
        self.client = client
        self.identifier = identifier

    async def make_jobset(
            self, identifier: str,
            nixexprinput: JobsetIncludeInput, nixexprpath: str,
            inputs: t.Dict[str, JobsetInput],
            description: str=None,
            emailoverride: str="",
    ) -> Jobset:
        if description is None:
            description = identifier
        for name, input in inputs.items():
            if input is nixexprinput:
                nixexprinput_name = name
                break
        else:
            nixexprinput_name = "nixexprinput"
            if nixexprinput_name in inputs:
                raise Exception(f"tried to default to name '{nixexprinput_name}' for the Nix expr input, "
                                "but you already used that name in your input dictionary. "
                                "Either explicitly include the Nix expr input in your input dictionary under any name, "
                                f"or don't use the name '{nixexprinput_name}'.")
            inputs = {**inputs, nixexprinput_name: nixexprinput}
        await self.client.http.put(f'/jobset/{self.identifier}/{identifier}', json.dumps({
            "identifier": identifier,
            "description": description,
            "checkinterval": "60",
            "enabled": "1",
            "visible": "1",
            "keepnr": "1",
            "nixexprinput": nixexprinput_name,
            "nixexprpath": nixexprpath,
            "enableemail": "1" if emailoverride else "0",
            "emailoverride": emailoverride,
            "inputs": {name:input.dict() for name, input in inputs.items()},
        }).encode())
        return Jobset(self, identifier)

class HydraClient:
    @staticmethod
    async def login(http: HTTPClient) -> 'HydraClient':
        await http.post("/login", json.dumps({'username': "sbaugh", 'password': "foobar"}).encode())
        return HydraClient(http)

    def __init__(self, http: HTTPClient) -> None:
        self.http = http

    async def make_project(self, identifier: str, displayname: str=None) -> Project:
        if displayname is None:
            displayname = identifier
        await self.http.put(f'/project/{identifier}', json.dumps({
            'identifier': identifier, 'displayname': displayname, 'enabled': '1', 'visible': '1',
        }).encode())
        return Project(self, identifier)

class TestHydra(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.thread = local.thread
        self.tmpdir = await self.thread.mkdtemp("test_hydra")
        self.path = self.tmpdir.path
        await update_symlink(self.thread, await self.thread.ram.ptr(self.tmpdir.parent/"test_hydra.current"), self.path)

        self.postgres = await start_postgres(self.nursery, self.thread, await self.thread.mkdir(self.path/"postgres"))
        await self.postgres.createuser("hydra")
        await self.postgres.createdb("hydra", owner="hydra")

        stubbin = await self.thread.mkdir(self.path/"stubbin")
        self.sendmail_stub = await StubServer.make(self.thread, local_store, stubbin, "sendmail")
        self.thread.environ['PATH'] = os.fsdecode(stubbin) + ':' + self.thread.environ['PATH']
        # start server
        # TODO I suppose this pidns thread is just going to be GC'd away... gotta make sure that works fine.
        pidns_thread = await self.thread.clone(CLONE.NEWUSER|CLONE.NEWPID)
        self.hydra = await start_hydra(
            self.nursery, pidns_thread, await self.thread.mkdir(self.path/"hydra"),
            "dbi:Pg:dbname=hydra;host=" + os.fsdecode(self.postgres.sockdir) + ";user=hydra;",
            DirectStore(store=self.path/"nix"/"store", state=self.path/"nix"/"state"),
        )

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def create_and_validate_job(self, client: HydraClient) -> None:
        project = await client.make_project('neato', "A neat project")
        job_name = "jobbymcjobface"
        jobset_dir = await self.thread.mkdir(self.path/"jobset")
        jobset_path = "trivial.nix"
        await self.thread.spit(jobset_dir/jobset_path, """{ string }:
{ """ + job_name + """ = builtins.derivation {
    name = "trivial";
    system = "x86_64-linux";
    builder = "/bin/sh";
    args = ["-c" "echo ${string} > $out; exit 0"];
  };
}""")
        email_address = "foo@bar"
        jobset = await project.make_jobset('trivial', PathInput(jobset_dir), jobset_path, {
            "string": StringInput("Hello World"),
        }, description="Some trivial jobset", emailoverride=email_address)

        args, sendmail_task = await self.sendmail_stub.accept()
        print("sendmail args", args)
        data = await sendmail_task.read_to_eof(sendmail_task.stdin)
        message = email.message_from_bytes(data)
        self.assertEqual(email_address,  message['To'])
        self.assertIn("Success", str(message['Subject']))
        self.assertEqual(project.identifier, message['X-Hydra-Project'])
        self.assertEqual(jobset.identifier,  message['X-Hydra-Jobset'])
        self.assertEqual(job_name, message['X-Hydra-Job'])

    async def test_hydra(self) -> None:
        client = await HydraClient.login(await HTTPClient.connect_unix(self.thread, self.hydra.addr))
        await self.create_and_validate_job(client)

    async def test_proxy(self) -> None:
        addr, _ = await start_fresh_nginx(self.nursery, self.thread, await self.thread.mkdir(self.path/"nginx"),
                                          self.hydra.addr.value)
        client = await HydraClient.login(await HTTPClient.connect_inet(self.thread, addr))
        await self.create_and_validate_job(client)

if __name__ == "__main__":
    import unittest
    unittest.main()
