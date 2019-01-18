
import rsyscall.io as rsc
import rsyscall.local_executables as local
import socket
import trio
import typing as t
import argparse

async def deploy_nix_daemon(remote_stdtask: rsc.StandardTask) -> rsc.Command:
    # TODO check if remote_nix_store exists, and skip this stuff if it does
    # copy the nix binaries over
    remote_tar = await rsc.which(remote_stdtask, b"tar")
    closure = await rsc.bootstrap_nix(local.nix_store, local.tar, rsc.local_stdtask, remote_tar, remote_stdtask)
    remote_nix_store = rsc.Command(
        remote_stdtask.task.base.make_path_from_bytes(bytes(local.nix_store.executable_path)), [b'nix-store'], {})
    await rsc.bootstrap_nix_database(local.nix_store, rsc.local_stdtask, remote_nix_store, remote_stdtask, closure)
    remote_nix_daemon = rsc.Command(
        remote_stdtask.task.base.make_path_from_bytes(bytes(local.nix_daemon.executable_path)), [b'nix-daemon'], {})
    return remote_nix_daemon

async def run_nix(host: rsc.SSHHost) -> None:
    "Deploys Nix from the local_stdtask to this remote_stdtask and runs nix-daemon there"
    ssh_child, remote_stdtask = await host.ssh(rsc.local_stdtask)
    nix_daemon = await deploy_nix_daemon(remote_stdtask)
    while True:
        try:
            # if there are more than 5 failures in 30 seconds, then there's an issue, we can't continue
            if too_many_failures:
                raise Exception("nix-daemon keeps failing for some reason")
            else:
                thread = await remote_stdtask.fork()
                child = await nix_daemon.exec(thread)
        except BaseException as exn:
            # TODO hmm, while working on this you might want to do a child.wait_for_exit,
            # then Ctrl-C out of it, then return that child.
            # basically, do the wait yourself then interrupt it.
            # How could we support that? How could we support Ctrl-C?
            child = await rsc.wish(rsc.ChildProcess, "I wish I had a working nix-daemon ChildProcess.")
        await child.wait_for_exit()
        note_exit()

async def isolate_exit(f, *args, **kwargs) -> None:
    while True:
        try:
            await f(*args, **kwargs)
        finally:
            await rsc.wish(type(None), "Oh no something has gone terribly wrong!")
            

email_address = 'me@example.com'
hosts = [
    # TODO let's try using an ssh to localhost; first we'll need to support making one without a tmpdir, using proc.
    rsc.SSHHost.make(local.ssh.args(['example.com']))
]

async def main() -> None:
    async with rsc.summon_email_genie(email_address):
        async with trio.open_nursery() as nursery:
            for host in hosts:
                nursery.start_soon(isolate_exit, run_nix, host)

if __name__ == '__main__':
    trio.run(main)
