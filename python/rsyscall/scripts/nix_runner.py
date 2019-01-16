import rsyscall.io as rsc
import socket
import trio
import typing as t
import argparse

async def deploy_nix_daemon(remote_stdtask) -> rsc.Command:
    pass

# The thing is, we don't want to use with statements,
# because those are hard to use in a REPL I suppose.
# well, we can always attach an asyncexitstack to the REPL, I guess.
# then we just use enter_context
async def run_nix(remote_stdtask) -> None:
    "Deploys Nix from the local_stdtask to this remote_stdtask and runs nix-daemon there"
    # so what should this look like? a loop or what?
    # essentially a loop I guess, but it'd be better if the wish could restart us.
    # maybe we could loop inside wish_on_failure?
    # maybe wish on failure could run the function instead of being a contextmanager?
    # hmm we also want to be able to handle an ssh problem, and recreate a connection.
    # I guess we can do the same kind of, repeated failure thing, for ssh.
    async with rsc.wish_on_failure("everything's gone catastrophically wrong, please help"):
        # TODO should we pull this out as well, and fail fast if we can't do the deployment?
        # Yes, I think so.
        # In fact, we should also run the executable.
        # Only after the executable is actually run, should we enter the long-lived stage.
        # Although, hmm. What exactly is the right thing to do here? Hm....
        # Dropping to a wish-repl is useful on any failure...
        # Well, some failures should bring down the system...
        # Should any failures bring down the system? Should we just keep sshing to the other hosts,
        # even if one host or even most hosts can't be reached?
        # Maybe not. Maybe we should just keep going.
        # If we decide to bring down everything, we can do that after the wish.
        # Yeah that makes sense...
        nix_daemon = await deploy_nix_daemon(remote_stdtask)
        while True:
            thread = await remote_stdtask.fork()
            child = await nix_daemon.exec(thread)
            while True:
                await child.wait_for_exit()
                # if there are more than 5 failures in 30 seconds, then there's an issue, we can't continue
                if too_many_failures:
                    # TODO hmm, while working on this you might want to do a child.wait_for_exit,
                    # then Ctrl-C out of it, then return that child.
                    # basically, do the wait yourself then interrupt it.
                    # How could we support that? How could we support Ctrl-C?
                    child = await rsc.wish(ChildProcess, "Starting nix-daemon keeps failing for some reason, "
                                           "I wish I had a working nix-daemon ChildProcess.")
                else:
                    note_failure()
                    thread = await remote_stdtask.fork()
                    child = await nix_daemon.exec(thread)

# this is very awkward
# what would we do/what are we doing in more programmatic terms?
# like, there's an exception, and we recover and restart?
# tail recursion is really what we want here...
# we want to have wish be able to just never return, just take over the new functionality.
# but, we can't do that, so instead, the wish can reassign f and args and kwargs,
# instead of doing a tail call
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
    remote_stdtasks = []
    for host in hosts:
        remote_stdtasks.append(await rsc.ssh(host))
    async with rsc.summon_email_genie(email_address):
        async with trio.open_nursery() as nursery:
            for host in hosts:
                nursery.start_soon(isolate_exit, run_nix, remote_stdtasks)

if __name__ == '__main__':
    trio.run(main)
