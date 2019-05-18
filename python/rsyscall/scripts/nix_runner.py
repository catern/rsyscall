import rsyscall.io as rsc
from rsyscall.io import Thread, wish, Wish, Path
import rsyscall.local_executables as local
import socket
import trio
import typing as t
import argparse
import rsyscall.tasks.local as local

async def deploy_nix_daemon(remote_thread: rsc.Thread,
                            container_thread: rsc.Thread) -> rsc.Command:
    "Deploy the Nix daemon from localhost"
    # TODO check if remote_nix_store exists, and skip this stuff if it does
    remote_tar = await rsc.which(remote_thread, b"tar")
    # copy the nix binaries over outside the container
    nix_bin = await rsc.deploy_nix_bin(local.nix_bin_dir, local.tar, local.thread,
                                       remote_tar, remote_thread,
                                       container_thread)
    return rsc.Command(nix_bin/"nix-daemon", [b'nix-daemon'], {})

async def make_container(root: Path, thread: Thread) -> Thread:
    # TODO do we need to keep track of this thread?
    thread = await thread.fork()
    container_thread = thread
    await container_thread.task.unshare_fs()
    await container_thread.task.chdir(root)
    # make the container in cwd
    await (container_thread.task.cwd()/"nix").mkdir()
    await container_thread.unshare_user()
    await container_thread.unshare_mount()
    # TODO chroot too I guess
    await container_thread.task.mount(b"nix", b"/nix", b"none", rsc.lib.MS_BIND, b"")
    return container_thread

async def run_nix(host: rsc.SSHHost) -> None:
    ssh_child, remote_thread = await host.ssh(local.thread)
    container_thread = await make_container(remote_thread.task.cwd(), remote_thread)
    await run_nix_daemon(remote_thread, container_thread)

async def run_nix_in_local_container() -> None:
    async with (await local.thread.mkdtemp()) as tmpdir:
        container_thread = await make_container(tmpdir, local.thread)
        await run_nix_daemon(local.thread, container_thread)

async def run_nix_daemon(remote_thread: rsc.Thread, container_thread: rsc.Thread) -> None:
    "Deploys Nix from the local_thread to this remote_thread and runs nix-daemon there"
    try:
        nix_daemon = await deploy_nix_daemon(remote_thread, container_thread)
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
                thread = await container_thread.fork()
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
    trio.run(LocalSSHHost.make, local.thread)
    # local.ssh.args('localhost').as_host()
]

async def main() -> None:
    # async with rsc.summon_email_genie(email_address):
    async with trio.open_nursery() as nursery:
        for host in hosts:
            nursery.start_soon(isolate_exit, run_nix, host)
        # for _ in range(1):
        #     nursery.start_soon(isolate_exit, run_nix_in_local_container)

if __name__ == '__main__':
    trio.run(main)
