import rsyscall.io as rsc
from rsyscall.io import StandardTask, wish, Wish
import rsyscall.local_executables as local
import socket
import trio
import typing as t
import argparse

async def deploy_nix_daemon(remote_stdtask: rsc.StandardTask,
                            container_stdtask: rsc.StandardTask) -> rsc.Command:
    "Deploy the Nix daemon from localhost"
    # TODO check if remote_nix_store exists, and skip this stuff if it does
    remote_tar = await rsc.which(remote_stdtask, b"tar")
    # copy the nix binaries over outside the container
    nix_bin = await rsc.deploy_nix_bin(local.nix_bin_dir, local.tar, rsc.local_stdtask,
                                       remote_tar, remote_stdtask,
                                       container_stdtask)
    return rsc.Command(nix_bin/"nix-daemon", [b'nix-daemon'], {})

async def make_container(stdtask: StandardTask) -> StandardTask:
    # TODO do we need to keep track of this thread?
    thread = await stdtask.fork()
    container_stdtask = thread.stdtask
    # make the container in cwd
    await (container_stdtask.task.cwd()/"nix").mkdir()
    await container_stdtask.unshare_user()
    await container_stdtask.unshare_mount()
    await container_stdtask.task.mount(b"nix", b"/nix", b"none", rsc.lib.MS_BIND, b"")
    return container_stdtask

async def run_nix(host: rsc.SSHHost) -> None:
    ssh_child, remote_stdtask = await host.ssh(rsc.local_stdtask)
    container_stdtask = await make_container(remote_stdtask)
    await run_nix_daemon(remote_stdtask, container_stdtask)

async def run_nix_in_local_container(host: rsc.SSHHost) -> None:
    # TODO need to make a directory, hmm...
    container_stdtask = await make_container(rsc.local_stdtask)
    await run_nix_daemon(rsc.local_stdtask, container_stdtask)

async def run_nix_daemon(remote_stdtask: rsc.StandardTask, container_stdtask: rsc.StandardTask) -> None:
    "Deploys Nix from the local_stdtask to this remote_stdtask and runs nix-daemon there"
    try:
        nix_daemon = await deploy_nix_daemon(remote_stdtask, container_stdtask)
    except:
        # TODO hmm we seem to be hitting an issue with,
        # we're running both ssh and cat on the same terminal,
        # and they read each other's inputs
        # we've set up ssh so the remote side inherits stdin and stdout and stderr from our terminal
        # but we want to lock stdin I guess
        # ugh ugh ugh ugh ugh ugh
        # well we can't really share stdin
        # i guess i can just not pass it over ssh hmm
        # i guess i should have some clean handling for stdin
        nix_daemon = await wish(Wish(rsc.Command, "Failed to deploy nix-daemon, do it and return it"))
    failures = 0
    while True:
        try:
            # if there are more than 5 failures in 30 seconds, then there's an issue, we can't continue
            if failures > 3:
                raise Exception("nix-daemon keeps failing for some reason")
            else:
                thread = await container_stdtask.fork()
                child = await nix_daemon.exec(thread)
        except:
            # TODO hmm, while working on this you might want to do a child.wait_for_exit,
            # then Ctrl-C out of it, then return that child.
            # basically, do the wait yourself then interrupt it.
            # How could we support that? How could we support Ctrl-C?
            child = await rsc.wish(Wish(rsc.ChildProcess, "I wish I had a working nix-daemon ChildProcess."))
        print("hello world!", failures)
        await child.wait_for_exit()
        failures += 1

async def isolate_exit(f, *args, **kwargs) -> None:
    # We'd rather be able to tail-call inside wish, instead of looping here; but you can't
    # tail-call in Python, so we're stuck with this loop, which can be used as a
    # trampoline by reassigning f/args/kwargs.
    while True:
        try:
            await f(*args, **kwargs)
        except:
            await rsc.wish(Wish(type(None), "Oh no something has gone terribly wrong!"))
        else:
            await rsc.wish(Wish(type(None), "The function terminated, we don't want that."))
            

from rsyscall.tests.test_ssh import LocalSSHHost
email_address = 'me@example.com'
hosts = [
    trio.run(LocalSSHHost.make, rsc.local_stdtask)
]

async def main() -> None:
    # async with rsc.summon_email_genie(email_address):
    async with trio.open_nursery() as nursery:
        for host in hosts:
            nursery.start_soon(isolate_exit, run_nix, host)

if __name__ == '__main__':
    trio.run(main)
