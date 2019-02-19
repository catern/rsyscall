import os
import requests
import trio
import rsyscall.io as rsc
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
        "inputs": {
            "trivial": {
                "value": os.fsdecode(parent),
                "type": "path",
            },
            "string": {
                "value": "hello world",
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
    await stdtask.run(initdb.args("--pgdata", pgdata))
    async with trio.open_nursery() as nursery:
        await nursery.start(stdtask.run, postgres.args('-D', pgdata))
        await stdtask.run(createuser.args("--no-superuser", "--no-createdb", "--no-createrole", "--pwprompt", "hydra"))
        await stdtask.run(createdb.args("--owner", "hydra", "hydra"))


        data = await (path/"hydra").mkdir()
        dbi = "dbi:Pg:dbname=hydra;host=localhost;user=hydra;"
        await stdtask.run(hydra_init.env(HYDRA_DBI=dbi, HYDRA_DATA=data))
        await stdtask.run(hydra_create_user.args(
            "sbaugh",
            "--full-name", "Spencer Baugh",
            "--email-address", "sbaugh@localhost",
            "--password", "foobar",
            "--role", "admin",
        ).env(HYDRA_DBI=dbi, HYDRA_DATA=data))
        # now to spawn things in the background
        await nursery.start(stdtask.run, hydra_server.env(HYDRA_DBI=dbi, HYDRA_DATA=data))
        await nursery.start(stdtask.run, hydra_evaluator.env(HYDRA_DBI=dbi, HYDRA_DATA=data))
        await nursery.start(stdtask.run, hydra_queue_runner.env(HYDRA_DBI=dbi, HYDRA_DATA=data))

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

if __name__ == "__main__":
    # trio.run(main)
    do_api_stuff()
