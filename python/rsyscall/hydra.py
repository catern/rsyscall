from __future__ import annotations
import abc
import json
import email
import h11
import socket
import time
import os
import requests
import trio
import rsyscall.io as rsc
import rsyscall.handle as handle
import typing as t
from rsyscall.trio_test_case import TrioTestCase
from rsyscall.io import StandardTask, RsyscallThread, Path, Command
from rsyscall.io import FileDescriptor, ReadableWritableFile, ChildProcess
from dataclasses import dataclass
import rsyscall.tasks.local as local

from rsyscall.inotify_watch import Inotify

from rsyscall.netinet.in_ import SockaddrIn
from rsyscall.sys.inotify import IN

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
                 write: t.Callable[[bytes], t.Awaitable[int]],
                 headers: t.List[t.Tuple[str, str]]) -> None:
        self.read = read
        self.write = write
        self.headers = headers
        self.connection = h11.Connection(our_role=h11.CLIENT)
        self.cookie: t.Optional[bytes] = None

    @staticmethod
    async def connect_unix(stdtask: StandardTask, sockpath: Path) -> HTTPClient:
        sock = await stdtask.task.socket_unix(socket.SOCK_STREAM)
        await rsc.robust_unix_connect(sockpath, sock)
        return HTTPClient(sock.read, sock.write, [
            ("Host", "localhost"),
            ("Accept", "application/json"),
            ("Content-Type", "application/json"),
        ])

    @staticmethod
    async def connect_inet(stdtask: StandardTask, addr: SockaddrIn) -> HTTPClient:
        sock = await stdtask.task.socket_inet(socket.SOCK_STREAM)
        await sock.connect(addr)
        return HTTPClient(sock.read, sock.write, [
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
    stdtask: StandardTask
    createuser_cmd: Command
    createdb_cmd: Command

    async def createuser(self, name: str) -> None:
        await self.stdtask.run(self.createuser_cmd.args("--host", self.sockdir, "--no-password", name))

    async def createdb(self, name: str, owner: str) -> None:
        await self.stdtask.run(self.createdb_cmd.args("--host", self.sockdir, "--owner", owner, name))

async def read_completely(task: rsc.Task, fd: handle.FileDescriptor) -> bytes:
    data = b''
    while True:
        new_data = await task.pread(fd, 4096, offset=len(data))
        if len(new_data) == 0:
            return data
        data += new_data

async def start_postgres(nursery, stdtask: StandardTask, path: Path) -> Postgres:
    initdb = await rsc.which(stdtask, "initdb")
    postgres = await rsc.which(stdtask, "postgres")
    createuser = await rsc.which(stdtask, "createuser")
    createdb = await rsc.which(stdtask, "createdb")

    data = path/"data"
    await stdtask.run(initdb.args("--pgdata", data, "--nosync", "--no-locale", "--auth=trust"))
    sockdir = await (path/"sock").mkdir()
    config = {
        # connection
        "listen_addresses": "''",
        "unix_socket_directories": f"'{os.fsdecode(sockdir)}'",
        # performance
        "fsync": "off",
        "synchronous_commit": "off",
        "full_page_writes": "off",
    }
    await rsc.spit(data/"postgresql.auto.conf", "\n".join([f"{key} = {value}" for key, value in config.items()]))
    inty = await Inotify.make(stdtask)
    watch = await inty.add(data.handle, IN.CLOSE_WRITE)

    await nursery.start(stdtask.run, postgres.args('-D', data))
    # pg_ctl uses the pid file to determine when postgres is up, so we do the same.
    pid_file_name = "postmaster.pid"
    pid_file = None
    while True:
        await watch.wait_until_event(IN.CLOSE_WRITE, pid_file_name)
        if pid_file is None:
            pid_file = await (data/pid_file_name).open(os.O_RDWR)
        pid_file_data = await read_completely(stdtask.task, pid_file.handle)
        try:
            # the postmaster status is on line 7
            # would be nice to get that from LOCK_FILE_LINE_PM_STATUS in pidfile.h
            pm_status = pid_file_data.split(b'\n')[7]
        except IndexError:
            pm_status = b""
        if b"ready" in pm_status:
            break
    await inty.close()
    return Postgres(sockdir, stdtask, createuser, createdb)

class NginxChild:
    # can support methods for reloading configuration, etc
    def __init__(self, child: ChildProcess) -> None:
        self.child = child

async def exec_nginx(thread: RsyscallThread, nginx: Command,
                     path: Path, config: handle.FileDescriptor,
                     listen_fds: t.List[handle.FileDescriptor]) -> ChildProcess:
    nginx_fds = [fd.maybe_copy(thread.stdtask.task.base) for fd in listen_fds]
    config_fd = config.maybe_copy(thread.stdtask.task.base)
    await thread.stdtask.unshare_files(going_to_exec=True)
    if nginx_fds:
        nginx_var = ";".join([str(await fd.as_argument()) for fd in nginx_fds]) + ';'
    else:
        nginx_var = ""
    await (path/"logs").mkdir()
    child = await thread.exec(
        nginx.env(NGINX=nginx_var).args("-p", path, "-c", f"/proc/self/fd/{await config_fd.as_argument()}"))
    return child

async def start_fresh_nginx(
        nursery, stdtask: StandardTask, path: Path, sockpath: Path
) -> t.Tuple[SockaddrIn, NginxChild]:
    nginx = await rsc.which(stdtask, "nginx")
    thread = await stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)
    sock = await thread.stdtask.task.socket_inet(socket.SOCK_STREAM)
    await sock.bind(SockaddrIn(0, 0x7F_00_00_01))
    addr: SockaddrIn = await sock.getsockname()
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
""" % (addr.port, os.fsencode(sockpath))
    await sock.listen(10)
    config_fd = await (path.with_task(thread.stdtask.task)/"nginx.conf").open(os.O_RDWR|os.O_CREAT)
    await config_fd.write_all(config)
    child = await exec_nginx(thread, nginx, path, config_fd.handle, [sock.handle])
    nursery.start_soon(child.check)
    return addr, NginxChild(child)

async def start_simple_nginx(nursery, stdtask: StandardTask, path: Path, sockpath: Path) -> NginxChild:
    nginx = await rsc.which(stdtask, "nginx")
    thread = await stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)
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
    sock = await thread.stdtask.task.socket_inet(socket.SOCK_STREAM)
    await sock.bind(SockaddrIn(3000, 0x7F_00_00_01))
    await sock.listen(10)
    config_fd = await (path.with_task(thread.stdtask.task)/"nginx.conf").open(os.O_RDWR|os.O_CREAT)
    await config_fd.write_all(config)
    child = await exec_nginx(thread, nginx, path, config_fd.handle, [sock.handle])
    nursery.start_soon(child.check)
    return NginxChild(child)

@dataclass
class Hydra:
    sockpath: Path

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

async def start_hydra(nursery, stdtask: StandardTask, path: Path, dbi: str, store: LocalStore) -> Hydra:
    # maybe have a version of this function which uses cached path locations?
    # or better yet, compiled in locations?
    hydra_init = await rsc.which(stdtask, "hydra-init")
    hydra_create_user = await rsc.which(stdtask, "hydra-create-user")
    hydra_server = await rsc.which(stdtask, "hydra-server")
    hydra_evaluator = await rsc.which(stdtask, "hydra-evaluator")
    hydra_queue_runner = await rsc.which(stdtask, "hydra-queue-runner")

    await stdtask.run(hydra_init.env(HYDRA_DBI=dbi, HYDRA_DATA=path))
    await stdtask.run(hydra_create_user.args(
        "sbaugh",
        "--full-name", "Spencer Baugh",
        "--email-address", "sbaugh@localhost",
        "--password", "foobar",
        "--role", "admin",
    ).env(HYDRA_DBI=dbi, HYDRA_DATA=path))

    # create config files
    config = {"email_notification": "1"}
    config_path = await rsc.spit(path/"hydra.conf", "\n".join([f"{key} = {value}" for key, value in config.items()]))
    hydra_env: t.Mapping[str, t.Union[str, bytes, os.PathLike]] = {
        'HYDRA_DBI': dbi,
        'HYDRA_DATA': path,
        'HYDRA_CONFIG': config_path,
        'NIX_REMOTE': store.uri(),
        'NIX_STATE_DIR': store.state_dir(),
    }
    # start server
    server_thread = await stdtask.fork()
    sock = await server_thread.stdtask.task.socket_unix(socket.SOCK_STREAM, cloexec=False)
    sockpath = path/"hydra_server.sock"
    await sock.bind(sockpath.unix_address())
    await sock.listen(10)
    ssport = os.fsdecode(sockpath)+"="+str(sock.handle.near.number)
    server_child = await server_thread.exec(hydra_server.env(
        **hydra_env, SERVER_STARTER_PORT=ssport))
    nursery.start_soon(server_child.check)
    # start evaluator, queue runner
    await nursery.start(stdtask.run, hydra_evaluator.env(**hydra_env))
    await nursery.start(stdtask.run, hydra_queue_runner.env(**hydra_env))
    return Hydra(sockpath)

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
        self.stdtask = local.stdtask
        self.tmpdir = await self.stdtask.mkdtemp("test_hydra")
        await rsc.update_symlink(self.tmpdir.parent, "test_hydra.current", os.fsdecode(self.tmpdir.name))
        self.path = self.tmpdir.path

        self.postgres = await start_postgres(self.nursery, self.stdtask, await (self.path/"postgres").mkdir())
        await self.postgres.createuser("hydra")
        await self.postgres.createdb("hydra", owner="hydra")

        stubbin = await (self.path/"stubbin").mkdir()
        self.sendmail_stub = await rsc.make_stub(self.stdtask, stubbin, "sendmail")
        self.stdtask.environment[b'PATH'] = os.fsencode(stubbin) + b':' + self.stdtask.environment[b'PATH']
        # start server
        # TODO I suppose this pidns thread is just going to be GC'd away... gotta make sure that works fine.
        pidns_thread = await self.stdtask.fork(newuser=True, newpid=True, fs=False, sighand=False)
        self.hydra = await start_hydra(
            self.nursery, pidns_thread.stdtask, await (self.path/"hydra").mkdir(),
            "dbi:Pg:dbname=hydra;host=" + os.fsdecode(self.postgres.sockdir) + ";user=hydra;",
            DirectStore(store=self.path/"nix"/"store", state=self.path/"nix"/"state"),
        )

    async def asyncTearDown(self) -> None:
        await self.tmpdir.cleanup()

    async def create_and_validate_job(self, client: HydraClient) -> None:
        project = await client.make_project('neato', "A neat project")
        job_name = "jobbymcjobface"
        jobset_dir = await (self.path/"jobset").mkdir()
        jobset_path = "trivial.nix"
        await rsc.spit(jobset_dir/jobset_path, """{ string }:
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
        data = await rsc.read_all(sendmail_task.stdin)
        message = email.message_from_bytes(data)
        self.assertEqual(email_address,  message['To'])
        self.assertIn("Success", message['Subject'])
        self.assertEqual(project.identifier, message['X-Hydra-Project'])
        self.assertEqual(jobset.identifier,  message['X-Hydra-Jobset'])
        self.assertEqual(job_name, message['X-Hydra-Job'])

    async def test_hydra(self) -> None:
        client = await HydraClient.login(await HTTPClient.connect_unix(self.stdtask, self.hydra.sockpath))
        await self.create_and_validate_job(client)

    async def test_proxy(self) -> None:
        addr, _ = await start_fresh_nginx(self.nursery, self.stdtask, await (self.path/"nginx").mkdir(),
                                          self.hydra.sockpath)
        client = await HydraClient.login(await HTTPClient.connect_inet(self.stdtask, addr))
        await self.create_and_validate_job(client)

if __name__ == "__main__":
    import unittest
    unittest.main()
