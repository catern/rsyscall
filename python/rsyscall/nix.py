"""Functions and classes for working with filesystem paths deployed with Nix

We use the nixdeps module to create build-time dependencies on Nix
derivations; setuptools will write out the paths and closures of the
Nix derivations we depend on.

We can use those dependencies by importing the `closure` module variables,
PackageClosure instances, which are independent of any specific thread.  To
turn a PackageClosure into a usable path, we can pass it to Store.realise,
which checks if the path is already deployed in that specific store,
and returns the path if so. If the path isn't deployed already,
Store.realise will deploy it for us.

"""
from __future__ import annotations
import typing as t
import os
import rsyscall.handle as handle
from rsyscall.thread import Thread, ChildThread
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
    "local_store",
    "nix",
    "Store",
    "bash_nixdep",
    "coreutils_nixdep",
    "hello_nixdep",
]

async def _exec_tar_copy_tree(src: ChildThread, src_paths: t.Sequence[t.Union[str, os.PathLike]], src_fd: FileDescriptor,
                              dest: ChildThread, dest_path: t.Union[str, os.PathLike], dest_fd: FileDescriptor) -> None:
    "Exec tar to copy files between two paths"
    dest_tar = await dest.environ.which("tar")
    src_tar = await dest.environ.which("tar")

    await dest.task.chdir(await dest.ram.ptr(dest_path))
    await dest.task.inherit_fd(dest_fd).dup2(dest.stdin)
    await dest_fd.close()
    dest_child = await dest.exec(dest_tar.args("--extract"))

    await src.task.inherit_fd(src_fd).dup2(src.stdout)
    await src_fd.close()
    src_child = await src.exec(src_tar.args(
        "--create", "--to-stdout", "--hard-dereference",
        "--owner=0", "--group=0", "--mode=u+rw,uga+r",
        *src_paths,
    ))
    await src_child.check()
    await dest_child.check()

async def copy_tree(src: Thread, src_paths: t.Sequence[t.Union[str, os.PathLike]], dest: Thread, dest_path: t.Union[str, os.PathLike]) -> None:
    """Copy all the listed `src_paths` to subdirectories of `dest_path`

    Example: if we pass src_paths=['/a/b', 'c'], dest_path='dest',
    then paths ['dest/b', 'dest/c'] will be created.
    """
    [(local_fd, dest_fd)] = await dest.connection.open_channels(1)
    src_fd = local_fd.move(src.task)
    await _exec_tar_copy_tree(await src.clone(), src_paths, src_fd,
                              await dest.clone(), dest_path, dest_fd)

async def _exec_nix_store_transfer_db(
        src: ChildThread, src_nix_store: Command, src_fd: FileDescriptor, closure: t.Sequence[t.Union[str, os.PathLike]],
        dest: ChildThread, dest_nix_store: Command, dest_fd: FileDescriptor,
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
        src: Thread, src_nix_store: Command, closure: t.Sequence[t.Union[str, os.PathLike]],
        dest: Thread, dest_nix_store: Command,
) -> None:
    "Bootstrap the store used by `dest` with the necessary database entries for `closure`, coming from `src`'s store"
    [(local_fd, dest_fd)] = await dest.open_channels(1)
    src_fd = local_fd.move(src.task)
    await _exec_nix_store_transfer_db(await src.clone(), src_nix_store, src_fd, closure,
                                      await dest.clone(), dest_nix_store, dest_fd)

async def enter_nix_container(store: Store, dest: Thread, dest_dir: Path) -> Store:
    """Move `dest` into a container in `dest_dir`, deploying Nix inside and returning the Store thus-created

    We can then use Store.realise to deploy other things into this container,
    which we can use from the `dest` thread or any of its children.

    """
    # we want to use our own container Nix store, not the global one on the system
    if 'NIX_REMOTE' in dest.environ:
        del dest.environ['NIX_REMOTE']
    # copy the binaries over
    await copy_tree(store.thread, store.nix.closure, dest, dest_dir)
    # enter the container
    await dest.unshare(CLONE.NEWNS|CLONE.NEWUSER)
    await dest.mount(dest_dir/"nix", "/nix", "none", MS.BIND, "")
    # init the database
    nix_store = Command(store.nix.path/'bin/nix-store', ['nix-store'], {})
    await bootstrap_nix_database(store.thread, nix_store, store.nix.closure, dest, nix_store)
    return Store(dest, store.nix)

async def deploy_nix_bin(store: Store, dest: Thread) -> Store:
    "Deploy the Nix binaries from `store` to /nix through `dest`"
    # copy the binaries over
    await copy_tree(store.thread, store.nix.closure, dest, Path("/nix"))
    # init the database
    nix_store = Command(store.nix.path/'bin/nix-store', ['nix-store'], {})
    await bootstrap_nix_database(store.thread, nix_store, store.nix.closure, dest, nix_store)
    return Store(dest, store.nix)

async def _exec_nix_store_import_export(
        src: ChildThread, src_nix_store: Command, src_fd: FileDescriptor,
        closure: t.Sequence[t.Union[str, os.PathLike]],
        dest: ChildThread, dest_nix_store: Command, dest_fd: FileDescriptor,
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

async def nix_deploy(src: Store, dest: Store, path: PackageClosure) -> None:
    "Deploy a PackageClosure from the src Store to the dest Store"
    [(local_fd, dest_fd)] = await dest.thread.open_channels(1)
    src_fd = local_fd.move(src.thread.task)
    await _exec_nix_store_import_export(
        await src.thread.clone(),
        Command(src.nix.path/'bin/nix-store', ['nix-store'], {}), src_fd, path.closure,
        await dest.thread.clone(),
        Command(dest.nix.path/'bin/nix-store', ['nix-store'], {}), dest_fd)

class Store:
    "Some Nix store, containing some derivations, and capable of realising new derivations"
    def __init__(self, thread: Thread, nix: PackageClosure) -> None:
        self.thread = thread
        self.nix = nix
        self.roots: t.Set[Path] = set()
        self._add_root(nix)

    def _add_root(self, package: PackageClosure) -> None:
        self.roots.add(Path(package.path))

    async def _create_root(self, package: PackageClosure, path: WrittenPointer[Path]) -> Path:
        # TODO create a Nix temp root pointing to this path
        self._add_root(package)
        # TODO would be cool to store and return a WrittenPointer[Path]
        return path.value

    async def realise(self, package: PackageClosure) -> Path:
        "Turn a PackageClosure into a Path, deploying it to this store if necessary"
        path = Path(package.path)
        if path in self.roots:
            return path
        ptr = await self.thread.ram.ptr(path)
        try:
            await self.thread.task.access(ptr, OK.R)
        except (PermissionError, FileNotFoundError):
            await nix_deploy(local_store, self, package)
            return await self._create_root(package, ptr)
        else:
            return await self._create_root(package, ptr)

    async def bin(self, package: PackageClosure, name: str) -> Command:
        "Realise this PackageClosure, then return a Command for the binary named `name`"
        path = await self.realise(package)
        return Command(path/"bin"/name, [name], {})

local_store: Store
nix: PackageClosure
# This is some hackery to make it possible to import rsyscall.nix without being
# built with Nix, as long as you don't use nix or local_store.
def _get_nix() -> PackageClosure:
    global nix
    if "nix" in globals():
        return nix
    else:
        from rsyscall._nixdeps.nix import closure
        nix = closure
        return nix

from rsyscall import local_thread

def __getattr__(name: str) -> t.Any:
    if name == "nix":
        return _get_nix()
    elif name == "local_store":
        global local_store
        local_store = Store(local_thread, _get_nix())
        return local_store
    raise AttributeError(f"module {__name__} has no attribute {name}")

from rsyscall._nixdeps.bash import closure as bash_nixdep
from rsyscall._nixdeps.coreutils import closure as coreutils_nixdep
from rsyscall._nixdeps.hello import closure as hello_nixdep
