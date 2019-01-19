import rsyscall.io as rsc
from rsyscall.io import StandardTask, wish, Wish
import rsyscall.local_executables as local
import socket
import trio
import typing as t
import argparse

async def deploy_nix_daemon(remote_stdtask: rsc.StandardTask,
                            container_stdtask: rsc.StandardTask) -> rsc.Command:
    # TODO check if remote_nix_store exists, and skip this stuff if it does
    # copy the nix binaries over outside the container
    remote_tar = await rsc.which(remote_stdtask, b"tar")
    # TODO indicate the destination of tar output somehow better than this
    # oh maybe we can just directly look at the root of the container? hmm.
    # maybe we can have the container open /nix, then use that in the remote_stdtask.
    closure = await rsc.bootstrap_nix(local.nix_store, local.tar, rsc.local_stdtask, remote_tar, remote_stdtask)
    remote_nix_store = rsc.Command(
        remote_stdtask.task.base.make_path_from_bytes(bytes(local.nix_store.executable_path)), [b'nix-store'], {})
    # run the database bootstrap inside the container
    await rsc.bootstrap_nix_database(local.nix_store, rsc.local_stdtask, remote_nix_store, container_stdtask, closure)
    remote_nix_daemon = rsc.Command(
        remote_stdtask.task.base.make_path_from_bytes(bytes(local.nix_daemon.executable_path)), [b'nix-daemon'], {})
    return remote_nix_daemon

async def enter_container(stdtask: StandardTask) -> StandardTask:
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
    "Deploys Nix from the local_stdtask to this remote_stdtask and runs nix-daemon there"
    ssh_child, remote_stdtask = await host.ssh(rsc.local_stdtask)
    container_stdtask = await enter_container(remote_stdtask)
    nix_daemon = await deploy_nix_daemon(remote_stdtask, container_stdtask)
    while True:
        failures = 0
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
            # hmm we want to print the exception.
            # basically, we want to see the whole stack trace:
            # above and below the wish.
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
