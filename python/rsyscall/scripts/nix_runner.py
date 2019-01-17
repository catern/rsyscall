import rsyscall.io as rsc
import socket
import trio
import typing as t
import argparse

async def deploy_nix_daemon(remote_stdtask) -> rsc.Command:
    pass

async def run_nix(host) -> None:
    "Deploys Nix from the local_stdtask to this remote_stdtask and runs nix-daemon there"
    remote_stdtask = await rsc.ssh(host)
    nix_daemon = await deploy_nix_daemon(remote_stdtask)
    while True:
        try:
            # if there are more than 5 failures in 30 seconds, then there's an issue, we can't continue
            if too_many_failures:
                raise Exception("nix-daemon keeps failing for some reason")
            else:
                thread = await remote_stdtask.fork()
                child = await nix_daemon.exec(thread)
        except as exn:
            # TODO hmm, while working on this you might want to do a child.wait_for_exit,
            # then Ctrl-C out of it, then return that child.
            # basically, do the wait yourself then interrupt it.
            # How could we support that? How could we support Ctrl-C?
            child = await rsc.wish(ChildProcess, "I wish I had a working nix-daemon ChildProcess.")
        await child.wait_for_exit()
        note_exit()

async def isolate_exit(f, *args, **kwargs) -> None:
    while True:
        async with rsc.wish_on_exit(msg):
            await f(*args, **kwargs)
            

email_address = 'me@example.com'
hosts = [
]

# Hmm we should also have a thing... I guess in the library...
# Where we find program dependencies with a file which Nix formats out.
# I guess we have some function which finds all the deps, and outputs a thing,
# and we can run that at build time.
# then we'll have a nice robust thing.
# and if it's not already run at build time, we run at import time
# and if it's already run, we don't 
# Right, I guess we just, um. Yes.
# We're able to run it at build time and it will output a JSON file.
# And at runtime it tries to load that JSON file, and instead runs directly if it can't
async def main() -> None:
    async with rsc.summon_email_genie(email_address):
        async with trio.open_nursery() as nursery:
            for host in hosts:
                nursery.start_soon(isolate_exit, run_nix, host)

if __name__ == '__main__':
    trio.run(main)
