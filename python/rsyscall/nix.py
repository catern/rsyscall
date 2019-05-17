from __future__ import annotations
import typing as t
import os
import rsyscall.handle as handle
from rsyscall.io import StandardTask
from rsyscall.io import Thread, ChildThread
from rsyscall.command import Command
import rsyscall.tasks.local as local
import trio
import struct
from dataclasses import dataclass
import nixdeps
import logging
from rsyscall.memory.ram import RAM, RAMThread
from rsyscall.handle import WrittenPointer, Pointer, FileDescriptor
from rsyscall.path import Path
from rsyscall.struct import Bytes

from rsyscall.sys.mount import MS
from rsyscall.fcntl import O
from rsyscall.unistd import Pipe, OK

__all__ = [
    "enter_nix_container",
    "local_store",
    "nix",
]

async def exec_tar_copy_tree(src: ChildThread, src_paths: t.List[Path], src_fd: FileDescriptor,
                             dest: ChildThread, dest_path: Path, dest_fd: FileDescriptor) -> None:
    dest_tar = await dest.environ.which("tar")
    src_tar = await dest.environ.which("tar")

    await dest.task.unshare_fs()
    await dest.task.chdir(await dest.ram.to_pointer(dest_path))
    await dest.unshare_files_and_replace({
        dest.stdin: dest_fd,
    })
    await dest_fd.close()
    dest_child = await dest.exec(dest_tar.args("--extract"))

    await src.unshare_files_and_replace({
        src.stdout: src_fd,
    })
    await src_fd.close()
    src_child = await src.exec(src_tar.args(
        "--create", "--to-stdout", "--hard-dereference",
        "--owner=0", "--group=0", "--mode=u+rw,uga+r",
        *src_paths,
    ))
    await src_child.check()
    await dest_child.check()

async def copy_tree(src: Thread, src_paths: t.List[Path], dest: Thread, dest_path: Path) -> None:
    [(local_fd, dest_fd)] = await dest.connection.open_channels(1)
    src_fd = local_fd.move(src.task)
    await exec_tar_copy_tree(await src.fork(), src_paths, src_fd,
                             await dest.fork(), dest_path, dest_fd)

async def exec_nix_store_transfer_db(
        src: ChildThread, src_nix_store: Command, src_fd: FileDescriptor, closure: t.List[Path],
        dest: ChildThread, dest_nix_store: Command, dest_fd: FileDescriptor,
) -> None:
    await dest.unshare_files_and_replace({
        dest.stdin: dest_fd,
    })
    await dest_fd.close()
    dest_child = await dest.exec(dest_nix_store.args("--load-db").env({'NIX_REMOTE': ''}))

    await src.unshare_files_and_replace({
        src.stdout: src_fd,
    })
    await src_fd.close()
    src_child = await src.exec(src_nix_store.args("--dump-db", *closure))
    await src_child.check()
    await dest_child.check()

async def bootstrap_nix_database(
        src: Thread, src_nix_store: Command, closure: t.List[Path],
        dest: Thread, dest_nix_store: Command,
) -> None:
    [(local_fd, dest_fd)] = await dest.open_channels(1)
    src_fd = local_fd.move(src.task)
    await exec_nix_store_transfer_db(await src.fork(), src_nix_store, src_fd, closure,
                                     await dest.fork(), dest_nix_store, dest_fd)

async def enter_nix_container(store: Store, dest: Thread, dest_dir: Path) -> Store:
    # we want to use our own container Nix store, not the global one on the system
    if 'NIX_REMOTE' in dest.environ:
        del dest.environ['NIX_REMOTE']
    # copy the binaries over
    await copy_tree(store.stdtask, store.nix.closure, dest, dest_dir)
    # enter the container
    await dest.unshare_user()
    await dest.unshare_mount()
    await dest.mount(os.fsencode(dest_dir/"nix"), b"/nix", b"none", MS.BIND, b"")
    # init the database
    nix_store = Command(store.nix.path/'bin/nix-store', ['nix-store'], {})
    await bootstrap_nix_database(store.stdtask, nix_store, store.nix.closure, dest, nix_store)
    return Store(dest, store.nix)

async def deploy_nix_bin(store: Store, dest: Thread) -> Store:
    # copy the binaries over
    await copy_tree(store.stdtask, store.nix.closure, dest, Path("/nix"))
    # init the database
    nix_store = Command(store.nix.path/'bin/nix-store', ['nix-store'], {})
    await bootstrap_nix_database(store.stdtask, nix_store, store.nix.closure, dest, nix_store)
    return Store(dest, store.nix)

async def exec_nix_store_import_export(
        src: ChildThread, src_nix_store: Command, src_fd: FileDescriptor, closure: t.List[Path],
        dest: ChildThread, dest_nix_store: Command, dest_fd: FileDescriptor,
) -> None:
    await dest.unshare_files_and_replace({
        dest.stdin: dest_fd,
    })
    await dest_fd.close()
    dest_child = await dest.exec(dest_nix_store.args("--import").env({'NIX_REMOTE': ''}))

    await src.unshare_files_and_replace({
        src.stdout: src_fd,
    })
    await src_fd.close()
    src_child = await src.exec(src_nix_store.args("--export", *closure))
    await src_child.check()
    await dest_child.check()

async def nix_deploy(src: Store, dest: Store, path: StorePath) -> None:
    [(local_fd, dest_fd)] = await dest.thread.open_channels(1)
    src_fd = local_fd.move(src.thread.task)
    await exec_nix_store_import_export(
        await src.thread.fork(), Command(src.nix.path/'bin/nix-store', ['nix-store'], {}), src_fd, path.closure,
        await dest.thread.fork(), Command(dest.nix.path/'bin/nix-store', ['nix-store'], {}), dest_fd)

async def canonicalize(thr: RAMThread, path: Path) -> Path:
    f = await thr.task.open(await thr.ram.to_pointer(path), O.PATH)
    size = 4096
    valid, _ = await thr.task.readlink(await thr.ram.to_pointer(f.as_proc_path()),
                                       await thr.ram.malloc_type(Path, size))
    if valid.bytesize() == size:
        # 4096 seems like a reasonable value for PATH_MAX
        raise Exception("symlink longer than 4096 bytes, giving up on readlinking it")
    return await valid.read()

class NixPath(Path):
    "A path in the Nix store, which can therefore be deployed to a remote host with Nix."
    @classmethod
    async def make(cls, thr: RAMThread, path: Path) -> NixPath:
        return cls(await canonicalize(thr, path))

    def __init__(self, *args) -> None:
        super().__init__(*args)
        root, nix, store = self.parts[:3]
        if root != b"/" or nix != b"nix" or store != b"store":
            raise Exception("path doesn't start with /nix/store")


import importlib.resources
import json

class StorePath:
    def __init__(self, path: Path, closure: t.List[Path]) -> None:
        self.path = path
        self.closure = closure

    @classmethod
    def _load_without_registering(self, name: str) -> StorePath:
        dep = nixdeps.import_nixdep('rsyscall._nixdeps', name)
        path = Path(dep.path)
        closure = [Path(elem) for elem in dep.closure]
        return StorePath(path, closure)

class Store:
    def __init__(self, stdtask: StandardTask, nix: StorePath) -> None:
        self.stdtask = stdtask
        self.thread = stdtask
        self.nix = nix
        self.roots: t.Dict[StorePath, Path] = {}
        self._add_root(nix, nix.path)

    def _add_root(self, store_path: StorePath, path: Path) -> None:
        self.roots[store_path] = path

    async def create_root(self, store_path: StorePath, path: WrittenPointer[Path]) -> Path:
        # TODO create a Nix temp root pointing to this path
        self._add_root(store_path, path.value)
        # TODO would be cool to store and return a WrittenPointer[Path]
        return path.value

    async def realise(self, store_path: StorePath) -> Path:
        if store_path in self.roots:
            return self.roots[store_path]
        ptr = await self.stdtask.ram.to_pointer(store_path.path)
        try:
            await self.stdtask.task.access(ptr, OK.R)
        except (PermissionError, FileNotFoundError):
            await nix_deploy(local_store, self, store_path)
            return await self.create_root(store_path, ptr)
        else:
            return await self.create_root(store_path, ptr)

    async def bin(self, store_path: StorePath, name: str) -> Command:
        path = await self.realise(store_path)
        return Command(path/"bin"/name, [name], {})

nix = StorePath._load_without_registering("nix")
local_store = Store(local.stdtask, nix)

def import_nix_dep(name: str) -> StorePath:
    store_path = StorePath._load_without_registering(name)
    # the local store has a root for every StorePath; that's where the
    # paths actually originally are.
    local_store._add_root(store_path, store_path.path)
    return store_path

rsyscall = import_nix_dep("rsyscall")
