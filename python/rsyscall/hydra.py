import h11
import socket
import time
import os
import requests
import trio
import rsyscall.io as rsc
import rsyscall.inotify as inotify
from rsyscall.io import StandardTask, Path

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

async def run_hydra(stdtask: StandardTask, path: Path) -> None:
    # postgres
    initdb = await rsc.which(stdtask, "initdb")
    createuser = await rsc.which(stdtask, "createuser")
    createdb = await rsc.which(stdtask, "createdb")
    postgres = await rsc.which(stdtask, "postgres")
    # hydra
    hydra_init = await rsc.which(stdtask, "hydra-init")
    hydra_create_user = await rsc.which(stdtask, "hydra-create-user")
    hydra_server = await rsc.which(stdtask, "hydra-server")
    hydra_evaluator = await rsc.which(stdtask, "hydra-evaluator")
    hydra_queue_runner = await rsc.which(stdtask, "hydra-queue-runner")
    
    # path...
    # 
    pgdata = path/"pgdata"
    await stdtask.run(initdb.args("--pgdata", pgdata, "--nosync", "--no-locale", "--auth=trust"))
    pgsock = path/"pgsock"
    await pgsock.mkdir()
    settings = {
        # connection
        "listen_addresses": "''",
        "unix_socket_directories": f"'{os.fsdecode(pgsock)}'",
        # performance
        "fsync": "off",
        "synchronous_commit": "off",
        "full_page_writes": "off",
    }
    await rsc.spit(pgdata/"postgresql.auto.conf", "\n".join([f"{key} = {value}" for key, value in settings.items()]))
    inty = await inotify.Inotify.make(stdtask)
    watch = await inty.add(pgdata.handle, inotify.Mask.CLOSE_WRITE)
    async with trio.open_nursery() as nursery:
        await nursery.start(stdtask.run, postgres.args('-D', pgdata))
        # pg_ctl uses the pid file to determine when postgres is up, so we do the same.
        # we don't actually look at the contents - just wait for postgres to be done writing
        # TODO actually do this right
        await trio.sleep(.5)
        await watch.wait_until_event(inotify.Mask.CLOSE_WRITE, "postmaster.pid")

        await stdtask.run(createuser.args("--host", pgsock, "--no-password", "hydra"))
        await stdtask.run(createdb.args("--host", pgsock, "--owner", "hydra", "hydra"))


        data = await (path/"hydra").mkdir()
        dbi = "dbi:Pg:dbname=hydra;host=" + os.fsdecode(pgsock) + ";user=hydra;"
        await stdtask.run(hydra_init.env(HYDRA_DBI=dbi, HYDRA_DATA=data))
        await stdtask.run(hydra_create_user.args(
            "sbaugh",
            "--full-name", "Spencer Baugh",
            "--email-address", "sbaugh@localhost",
            "--password", "foobar",
            "--role", "admin",
        ).env(HYDRA_DBI=dbi, HYDRA_DATA=data))

        # start server
        server_thread = await stdtask.fork()
        sock = await server_thread.stdtask.task.socket_unix(socket.SOCK_STREAM, cloexec=False)
        addr = (path/"sock").unix_address()
        await sock.bind(addr)
        await sock.listen(10)
        server_child = await server_thread.exec(hydra_server.env(
            HYDRA_DBI=dbi, HYDRA_DATA=data, SERVER_STARTER_PORT=f"3000={sock.handle.near.number};"))
        nursery.start_soon(server_child.check)
        # start evaluator, queue runner
        await nursery.start(stdtask.run, hydra_evaluator.env(HYDRA_DBI=dbi, HYDRA_DATA=data))
        await nursery.start(stdtask.run, hydra_queue_runner.env(HYDRA_DBI=dbi, HYDRA_DATA=data))
        # connect and send http requests
        await trio.sleep(3)
        print("doing stuff")
        sock = await stdtask.task.socket_unix(socket.SOCK_STREAM)
        # TODO hmm annoying, because our address is a unix address,
        # not an inet address,
        # starman is confused.
        await sock.connect(addr)
        conn = h11.Connection(our_role=h11.CLIENT)
        headers = [
            ("Host", "localhost"),
            ("Referer", "http://localhost:3000"),
            ("Accept", "application/json"),
        ]
        await sock.write(conn.send(h11.Request(method="GET", target="/", headers=headers)))
        await sock.write(conn.send(h11.EndOfMessage()))
        data = await sock.read()
        conn.receive_data(data)
        print(conn.next_event())
        # TODO use h11
        # hmm it would be nice to avoid maintaining a connection I guess.

async def main() -> None:
    stdtask = rsc.local_stdtask
    path = Path.from_bytes(stdtask.task, stdtask.environment[b'HOME'])/"hydra"
    await path.mkdir()
    await run_hydra(rsc.local_stdtask, path)

import rsyscall
trivial_path = Path.from_bytes(
    rsc.local_stdtask.task,
    rsyscall.__spec__.loader.get_resource_reader(rsyscall.__spec__.name).resource_path('trivial.nix'))

def do_api_stuff() -> None:
    session = requests.Session()
    base = 'http://localhost:3000'
    session.headers.update({'Referer': base})
    session.headers.update({'Accept': 'application/json'})

    session.hooks = {
        # 'response': lambda r, *args, **kwargs: r.raise_for_status()
    }
    login(session, base, 'sbaugh', 'foobar')
    project_identifier = 'trivial'
    new_project(session, base, project_identifier)
    new_jobset(session, base, project_identifier, 'trivial', trivial_path)

# for builds:
# - we need to be a trusted user
# - we need a signing key and autosigning

# ah we can just use a different prefix for the nix store! that would be totally fine!

# okay so let's try and use sqlite to speed up startup?
# maybe initdb can be configured to not sync? maybe we can do postgres in-memory?
# yeah if we don't pass a HYDRA_DBI it uses sqlite.
# or we can just do it ourselves...

if __name__ == "__main__":
    trio.run(main)
    # do_api_stuff()
