"""Functions and classes for working with filesystem paths deployed with Nix

We use the nixdeps module to create build-time dependencies on Nix
derivations; setuptools will write out the paths and closures of the
Nix derivations we depend on.

We can use those dependencies by importing the `closure` module variables,
PackageClosure instances, which are independent of any specific process.  To
turn a PackageClosure into a usable path, we can pass it to `deploy`,
which checks if the path is already deployed in that specific store,
and returns the path if so. If the path isn't deployed already,
`deploy` will deploy it for us.

"""
from __future__ import annotations
import typing as t
import os
import rsyscall.handle as handle
from rsyscall import local_process
from rsyscall.thread import Process, ChildProcess
from rsyscall.command import Command
import trio
import struct
from dataclasses import dataclass
import nixdeps
from nixdeps import PackageClosure
import logging
from rsyscall.handle import WrittenPointer, Pointer, FileDescriptor
from rsyscall.path import Path

from rsyscall.sys.mount import MS
from rsyscall.fcntl import O
from rsyscall.sched import CLONE
from rsyscall.unistd import Pipe, OK

__all__ = [
    "copy_tree",
    "enter_nix_container",
    "deploy",
]

async def _exec_tar_copy_tree(src: ChildProcess, src_paths: t.Sequence[t.Union[str, os.PathLike]], src_fd: FileDescriptor,
                              dest: ChildProcess, dest_path: t.Union[str, os.PathLike], dest_fd: FileDescriptor) -> None:
    "Exec tar to copy files between two paths"
    dest_tar = await dest.environ.which("tar")
    src_tar = await dest.environ.which("tar")

    await dest.task.chdir(await dest.task.ptr(dest_path))
    await dest.task.inherit_fd(dest_fd).dup2(dest.stdin)
    await dest_fd.close()
    dest_child = await dest.exec(dest_tar.args("--extract"))

    await src.task.inherit_fd(src_fd).dup2(src.stdout)
    await src_fd.close()
    src_child = await src.exec(src_tar.args(
        "--create", "--to-stdout", "--hard-dereference",
        "--owner=0", "--group=0", "--mode=u+rw,uga+r",
        # suppress a tar warning about trying to compress an absolute path
        "--directory=/", *[Path(src_path).relative_to("/") for src_path in src_paths],
    ))
    await src_child.check()
    await dest_child.check()

async def copy_tree(src: Process, src_paths: t.Sequence[t.Union[str, os.PathLike]], dest: Process, dest_path: t.Union[str, os.PathLike]) -> None:
    """Copy all the listed `src_paths` to subdirectories of `dest_path`

    Example: if we pass src_paths=['/a/b', '/c'], dest_path='dest',
    then paths ['dest/a/b', 'dest/c'] will be created.

    Requires all the paths to be absolute, because that was easier with tar.
    """
    [(local_fd, dest_fd)] = await dest.connection.open_channels(1)
    src_fd = local_fd.move(src.task)
    await _exec_tar_copy_tree(await src.fork(), src_paths, src_fd,
                              await dest.fork(), dest_path, dest_fd)

async def _exec_nix_store_transfer_db(
        src: ChildProcess, src_nix_store: Command, src_fd: FileDescriptor, closure: t.Sequence[t.Union[str, os.PathLike]],
        dest: ChildProcess, dest_nix_store: Command, dest_fd: FileDescriptor,
) -> None:
    "Exec nix-store to copy the Nix database for a closure between two stores"
    await dest.task.inherit_fd(dest_fd).dup2(dest.stdin)
    await dest_fd.close()
    dest_child = await dest.exec(dest_nix_store.args("--load-db").env({'NIX_REMOTE': ''}))

    await src.task.inherit_fd(src_fd).dup2(src.stdout)
    await src_fd.close()
    src_child = await src.exec(src_nix_store.args("--dump-db", *closure))
    await src_child.check()
    await dest_child.check()

async def bootstrap_nix_database(
        src: Process, src_nix_store: Command, closure: t.Sequence[t.Union[str, os.PathLike]],
        dest: Process, dest_nix_store: Command,
) -> None:
    "Bootstrap the store used by `dest` with the necessary database entries for `closure`, coming from `src`'s store"
    [(local_fd, dest_fd)] = await dest.open_channels(1)
    src_fd = local_fd.move(src.task)
    await _exec_nix_store_transfer_db(await src.fork(), src_nix_store, src_fd, closure,
                                      await dest.fork(), dest_nix_store, dest_fd)

async def enter_nix_container(
        src: Process, nix: PackageClosure,
        dest: Process, dest_dir: Path,
) -> None:
    """Move `dest` into a container in `dest_dir`, deploying Nix inside.

    We can then use `deploy` to deploy other things into this container,
    which we can use from the `dest` process or any of its children.

    """
    # we want to use our own container Nix store, not the global one on the system
    if 'NIX_REMOTE' in dest.environ:
        del dest.environ['NIX_REMOTE']
    # copy the binaries over
    await copy_tree(src, nix.closure, dest, dest_dir)
    # enter the container
    await dest.unshare(CLONE.NEWNS|CLONE.NEWUSER)
    await dest.mount(dest_dir/"nix", "/nix", "none", MS.BIND, "")
    # init the database
    nix_store = Command(nix.path/'bin/nix-store', ['nix-store'], {})
    await bootstrap_nix_database(src, nix_store, nix.closure, dest, nix_store)
    # add nix.path to PATH; TODO add a real API for this
    dest.environ.path.paths.append(Path(nix.path/'bin'))

async def _exec_nix_store_import_export(
        src: ChildProcess, src_nix_store: Command, src_fd: FileDescriptor,
        closure: t.Sequence[t.Union[str, os.PathLike]],
        dest: ChildProcess, dest_nix_store: Command, dest_fd: FileDescriptor,
) -> None:
    "Exec nix-store to copy a closure of paths between two stores"
    await dest.task.inherit_fd(dest_fd).dup2(dest.stdin)
    await dest_fd.close()
    dest_child = await dest.exec(dest_nix_store.args("--import").env({'NIX_REMOTE': ''}))

    await src.task.inherit_fd(src_fd).dup2(src.stdout)
    await src_fd.close()
    src_child = await src.exec(src_nix_store.args("--export", *closure))
    await src_child.check()
    await dest_child.check()

async def _deploy(src: Process, dest: Process, path: PackageClosure) -> None:
    "Deploy a PackageClosure from the src Process to the dest Process"
    [(local_fd, dest_fd)] = await dest.open_channels(1)
    src_fd = local_fd.move(src.task)
    await _exec_nix_store_import_export(
        await src.fork(),
        await src.environ.which('nix-store'),
        src_fd, path.closure,
        await dest.fork(),
        await dest.environ.which('nix-store'),
        dest_fd)

class PackagePath(Path):
    "A Path with a few helper methods useful for Nix packages"
    def bin(self, name: str) -> Command:
        return Command(self/"bin"/name, [name], {})

async def deploy(process: Process, package: PackageClosure) -> PackagePath:
    "Deploy a PackageClosure to the filesystem of this Process"
    if process is not local_process:
        # for remote processes, we need to check if it's actually there,
        # and deploy it if it's not there.
        # TODO we should really make and return a Nix GC root, too...
        ptr = await process.ptr(package.path)
        try:
            await process.task.access(ptr, OK.R)
        except (PermissionError, FileNotFoundError):
            await _deploy(local_process, process, package)
    return PackagePath(package.path)
