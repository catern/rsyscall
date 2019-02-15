import trio
import rsyscall.io as rsc
from rsyscall.io import StandardTask, Path

# launch postgres
# I guess just do all these commands, hmm.
# A thing to run shell commands would be useful I s'pose.
# I guess somefin wot takes a Command and executes it.

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

trio.run(main)
