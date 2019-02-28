import json
import email
import h11
import socket
import time
import os
import requests
import trio
import rsyscall.io as rsc
import rsyscall.inotify as inotify
import typing as t
from rsyscall.io import StandardTask, Path, Command
from rsyscall.io import FileDescriptor, ReadableWritableFile
from dataclasses import dataclass

# launch postgres
# I guess just do all these commands, hmm.
# A thing to run shell commands would be useful I s'pose.
# I guess somefin wot takes a Command and executes it.
def login(session, base: str, username: str, password: str) -> None:
    response = session.post(base + '/login', json={'username': username, 'password': password})
    print(response.text)
    response.raise_for_status()

def new_project(session, base: str, identifier: str) -> None:
    response = session.put(base + f'/project/{identifier}', json={
        'identifier': identifier, 'displayname': 'Trivial', 'enabled': '1', 'visible': '1',
    })
    print(response.text)
    response.raise_for_status()

def new_jobset(session, base: str, project: str, identifier: str, path: Path) -> None:
    parent, name = path.split()
    response = session.put(base + f'/jobset/{project}/{identifier}', json={
        "identifier": identifier,
        "description": "Trivial",
        "checkinterval": "60",
        "enabled": "1",
        "visible": "1",
        "keepnr": "1",
        "nixexprinput": "trivial",
        "nixexprpath": os.fsdecode(name),
        "enableemail": "1",
        "emailoverride": "sbaugh@localhost",
        "inputs": {
            "trivial": {
                "value": os.fsdecode(parent),
                "type": "path",
            },
            "string": {
                "value": "hello world " + str(time.time()),
                "type": "string",
            },
        },
    })
    print(response.text)
    response.raise_for_status()

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
        self.cookies: t.Optional[bytes] = None

    async def next_event(self) -> t.Any:
        while True:
            event = self.connection.next_event()
            if event is h11.NEED_DATA:
                data = await self.read()
                self.connection.receive_data(data)
                continue
            return event

    def get_headers(self) -> t.List[t.Tuple[str, str]]:
        if self.cookies is None:
            return self.headers
        else:
            return [*self.headers, ("Cookie", self.cookies)]

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
            self.cookies = set_cookie
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
    inty = await inotify.Inotify.make(stdtask)
    watch = await inty.add(data.handle, inotify.Mask.CLOSE_WRITE)

    await nursery.start(stdtask.run, postgres.args('-D', data))
    # pg_ctl uses the pid file to determine when postgres is up, so we do the same.
    # we don't actually look at the contents - just wait for postgres to be done writing
    # TODO actually do this right
    await trio.sleep(.5)
    await watch.wait_until_event(inotify.Mask.CLOSE_WRITE, "postmaster.pid")
    await inty.aclose()
    return Postgres(sockdir, stdtask, createuser, createdb)

@dataclass
class Hydra:
    sockpath: Path

async def start_hydra(nursery, stdtask: StandardTask, path: Path, dbi: str) -> Hydra:
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


class HydraClient:
    @staticmethod
    async def connect(stdtask: StandardTask, hydra: Hydra) -> 'HydraClient':
        sock = await stdtask.task.socket_unix(socket.SOCK_STREAM)
        await sock.connect(hydra.sockpath.unix_address())
        client = HTTPClient(sock.read, sock.write, [
            ("Host", "localhost"),
            # ("Referer", "http://localhost:3000/"),
            ("Referer", "http://localhost/"),
            ("Accept", "application/json"),
        ])
        await client.post("/login", json.dumps({'username': "sbaugh", 'password': "foobar"}).encode())
        return HydraClient(client)

    def __init__(self, http_client: HTTPClient) -> None:
        self.http_client = http_client

    async def make_project(self) -> None:
        await self.http_client.put('/project/trivial', json.dumps({
            'identifier': 'trivial', 'displayname': 'Trivial', 'enabled': '1', 'visible': '1',
        }).encode())

    async def make_jobset(self) -> None:
        parent, name = trivial_path.split()
        await self.http_client.put('/jobset/trivial/trivial', json.dumps({
            "identifier": "trivial",
            "description": "Trivial",
            "checkinterval": "60",
            "enabled": "1",
            "visible": "1",
            "keepnr": "1",
            "nixexprinput": "trivial",
            "nixexprpath": os.fsdecode(name),
            "enableemail": "1",
            "emailoverride": "sbaugh@localhost",
            "inputs": {
                "trivial": {
                    "value": os.fsdecode(parent),
                    "type": "path",
                },
                "string": {
                    "value": "hello world " + str(time.time()),
                    "type": "string",
                },
            },
        }).encode())
        

async def run_hydra(stdtask: StandardTask, path: Path) -> None:
    async with trio.open_nursery() as nursery:
        postgres = await start_postgres(nursery, stdtask, await (path/"postgres").mkdir())

        await postgres.createuser("hydra")
        await postgres.createdb("hydra", owner="hydra")

        stubbin = await (path/"stubbin").mkdir()
        sendmail_stub = await rsc.make_stub(stdtask, stubbin, "sendmail")
        stdtask.environment[b'PATH'] = os.fsencode(stubbin) + b':' + stdtask.environment[b'PATH']
        # start server
        hydra = await start_hydra(nursery, stdtask, await (path/"hydra").mkdir(), 
                                  "dbi:Pg:dbname=hydra;host=" + os.fsdecode(postgres.sockdir) + ";user=hydra;")
        # connect and send http requests
        print("doing stuff")
        client = await HydraClient.connect(stdtask, hydra)
        await client.make_project()
        await client.make_jobset()

        args, sendmail_task = await sendmail_stub.accept()
        print("sendmail args", args)
        data = await rsc.read_until_eof(sendmail_task.stdin)
        message = email.message_from_bytes(data)
        print(message)
        print(message['X-Hydra-Project'], 'trivial')
        print(message['X-Hydra-Jobset'], 'trivial')
        print(message['X-Hydra-Job'], 'trivial')
        print(message['Subject'].startswith("Success"))

async def main() -> None:
    stdtask = rsc.local_stdtask
    path = Path.from_bytes(stdtask.task, stdtask.environment[b'HOME'])/"hydra"
    await path.mkdir()
    await run_hydra(rsc.local_stdtask, path)

import rsyscall
trivial_path = Path.from_bytes(
    rsc.local_stdtask.task,
    rsyscall.__spec__.loader.get_resource_reader(rsyscall.__spec__.name).resource_path('trivial.nix'))

# for builds:
# - we need to be a trusted user
# - we need a signing key and autosigning

# ah we can just use a different prefix for the nix store! that would be totally fine!

# okay so let's try and use sqlite to speed up startup?
# maybe initdb can be configured to not sync? maybe we can do postgres in-memory?
# yeah if we don't pass a HYDRA_DBI it uses sqlite.
# or we can just do it ourselves...

import unittest
import functools
from trio._core._run import Nursery

class TrioTestCase(unittest.TestCase):
    nursery: Nursery

    async def asyncSetUp(self) -> None:
        pass

    async def asyncTearDown(self) -> None:
        pass

    def __init__(self, methodName='runTest') -> None:
        test = getattr(self, methodName)
        @functools.wraps(test)
        async def test_with_setup() -> None:
            async with trio.open_nursery() as nursery:
                self.nursery = nursery
                await self.asyncSetUp()
                await test()
                await self.asyncTearDown()
                nursery.cancel_scope.cancel()
        @functools.wraps(test_with_setup)
        def sync_test_with_setup() -> None:
            trio.run(test_with_setup)
        setattr(self, methodName, sync_test_with_setup)
        super().__init__(methodName)

class TestHydra(TrioTestCase):
    async def asyncSetUp(self) -> None:
        self.stdtask = rsc.local_stdtask
        self.path = Path.from_bytes(self.stdtask.task, self.stdtask.environment[b'HOME'])/"hydra"
        await self.path.mkdir()

        self.postgres = await start_postgres(self.nursery, self.stdtask, await (self.path/"postgres").mkdir())
        await self.postgres.createuser("hydra")
        await self.postgres.createdb("hydra", owner="hydra")

        stubbin = await (self.path/"stubbin").mkdir()
        self.sendmail_stub = await rsc.make_stub(self.stdtask, stubbin, "sendmail")
        self.stdtask.environment[b'PATH'] = os.fsencode(stubbin) + b':' + self.stdtask.environment[b'PATH']
        # start server
        self.hydra = await start_hydra(self.nursery, self.stdtask, await (self.path/"hydra").mkdir(), 
                                       "dbi:Pg:dbname=hydra;host=" + os.fsdecode(self.postgres.sockdir) + ";user=hydra;")
        self.client = await HydraClient.connect(self.stdtask, self.hydra)
        
    async def test_hydra(self) -> None:
        await self.client.make_project()
        await self.client.make_jobset()

        args, sendmail_task = await self.sendmail_stub.accept()
        print("sendmail args", args)
        data = await rsc.read_until_eof(sendmail_task.stdin)
        message = email.message_from_bytes(data)
        self.assertEqual('trivial', message['X-Hydra-Project'])
        self.assertEqual('trivial', message['X-Hydra-Jobset'])
        self.assertEqual('trivial', message['X-Hydra-Job'])
        self.assertIn("Success", message['Subject'])

if __name__ == "__main__":
    unittest.main()
