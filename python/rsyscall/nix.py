from __future__ import annotations
import typing as t
import os
import rsyscall.handle as handle
from rsyscall.io import StandardTask, read_all, Command, MemFileDescriptor, Path
import rsyscall.tasks.local as local
import trio
import struct
from dataclasses import dataclass
import nixdeps
import logging
from rsyscall.memory.ram import RAMThread

from rsyscall.sys.mount import MS
from rsyscall.fcntl import O
from rsyscall.unistd import Pipe

async def bootstrap_nix(
        src_nix_store: Command, src_tar: Command, src_task: StandardTask,
        dest_tar: Command, dest_task: StandardTask, dest_dir: handle.FileDescriptor,
) -> t.List[bytes]:
    "Copies the Nix binaries into dest task's CWD. Returns the list of paths in the closure."
    query_thread = await src_task.fork()
    query_pipe = await (await src_task.task.base.pipe(await src_task.ram.malloc_struct(Pipe))).read()
    query_stdout = query_pipe.write.move(query_thread.stdtask.task.base)
    await query_thread.stdtask.unshare_files(going_to_exec=True)
    await query_thread.stdtask.stdout.replace_with(query_stdout)
    await query_thread.exec(
        src_nix_store.args("--query", "--requisites", src_nix_store.executable_path))
    closure = (await read_all(MemFileDescriptor(src_task.ram, query_pipe.read))).split()

    src_tar_thread = await src_task.fork()
    dest_tar_thread = await dest_task.fork()
    [(access_side, dest_tar_stdin)] = await dest_tar_thread.stdtask.open_channels(1)
    src_tar_stdout = access_side.move(src_tar_thread.stdtask.task.base)

    await dest_tar_thread.stdtask.task.base.unshare_fs()
    await dest_tar_thread.stdtask.task.base.fchdir(dest_dir)
    await dest_tar_thread.stdtask.unshare_files(going_to_exec=True)
    await dest_tar_thread.stdtask.stdin.replace_with(dest_tar_stdin)
    child_task = await dest_tar_thread.exec(dest_tar.args("--extract"))

    await src_tar_thread.stdtask.unshare_files(going_to_exec=True)
    await src_tar_thread.stdtask.stdout.replace_with(src_tar_stdout)
    await src_tar_thread.exec(src_tar.args(
        "--create", "--to-stdout", "--hard-dereference",
        "--owner=0", "--group=0", "--mode=u+rw,uga+r",
        *closure,
    ))
    await child_task.wait_for_exit()
    return closure

async def bootstrap_nix_database(
        src_nix_store: Command, src_task: StandardTask,
        dest_nix_store: Command, dest_task: StandardTask,
        closure: t.List[bytes],
) -> None:
    dump_db_thread = await src_task.fork()
    load_db_thread = await dest_task.fork()
    [(access_side, load_db_stdin)] = await load_db_thread.stdtask.open_channels(1)
    dump_db_stdout = access_side.move(dump_db_thread.stdtask.task.base)

    await load_db_thread.stdtask.unshare_files(going_to_exec=True)
    await load_db_thread.stdtask.stdin.replace_with(load_db_stdin)
    child_task = await load_db_thread.exec(dest_nix_store.args("--load-db").env({'NIX_REMOTE': ''}))

    await dump_db_thread.stdtask.unshare_files(going_to_exec=True)
    await dump_db_thread.stdtask.stdout.replace_with(dump_db_stdout)
    await dump_db_thread.exec(src_nix_store.args("--dump-db", *closure))
    await child_task.check()

async def create_nix_container(
        src_nix_bin: handle.Path, src_task: StandardTask,
        dest_task: StandardTask,
) -> handle.Path:
    dest_nix_bin = dest_task.task.base.make_path_handle(src_nix_bin)
    src_nix_store = Command(src_nix_bin/'nix-store', [b'nix-store'], {})
    dest_nix_store = Command(dest_nix_bin/'nix-store', [b'nix-store'], {})
    # TODO check if dest_nix_bin exists, and skip this stuff if it does
    # copy the nix binaries over
    src_tar = await src_task.environ.which("tar")
    dest_tar = await dest_task.environ.which("tar")
    closure = await bootstrap_nix(src_nix_store, src_tar, src_task, dest_tar, dest_task) # type: ignore

    # mutate dest_task so that it is nicely namespaced for the Nix container
    await dest_task.unshare_user()
    await dest_task.unshare_mount()
    await dest_task.mount(b"nix", b"/nix", b"none", MS.BIND, b"")
    await bootstrap_nix_database(src_nix_store, src_task, dest_nix_store, dest_task, closure)
    return dest_nix_bin

async def deploy_nix_bin(
        src_nix_bin: NixPath, src_tar: Command, src_task: StandardTask,
        deploy_tar: Command, deploy_task: StandardTask,
        dest_task: StandardTask,
) -> handle.Path:
    dest_nix_bin = NixPath(src_nix_bin)
    src_nix_store = Command(src_nix_bin/'nix-store', [b'nix-store'], {})
    dest_nix_store = Command(dest_nix_bin/'nix-store', [b'nix-store'], {})
    # TODO check if dest_nix_bin exists, and skip this stuff if it does
    rootdir = await dest_task.task.base.open(await dest_task.ram.to_pointer(handle.Path("/")), O.DIRECTORY|O.CLOEXEC)
    closure = await bootstrap_nix(src_nix_store, src_tar, src_task, deploy_tar, deploy_task, rootdir)
    await bootstrap_nix_database(src_nix_store, src_task, dest_nix_store, dest_task, closure)
    return dest_nix_bin

async def nix_deploy(
        src_nix_bin: handle.Path, src_path: handle.Path, src_task: StandardTask,
        dest_nix_bin: handle.Path, dest_task: StandardTask,
) -> handle.Path:
    dest_path = dest_task.task.base.make_path_handle(src_path)

    query_thread = await src_task.fork()
    query_pipe = await (await src_task.task.base.pipe(await src_task.ram.malloc_struct(Pipe))).read()
    query_stdout = query_pipe.write.move(query_thread.stdtask.task.base)
    await query_thread.stdtask.unshare_files(going_to_exec=True)
    await query_thread.stdtask.stdout.replace_with(query_stdout)
    await query_thread.exec(Command(src_nix_bin/"nix-store", [b"nix-store"], {}).args("--query", "--requisites", src_path))
    closure = (await read_all(MemFileDescriptor(src_task.ram, query_pipe.read))).split()

    export_thread = await src_task.fork()
    import_thread = await dest_task.fork()
    [(access_side, import_stdin)] = await import_thread.stdtask.open_channels(1)
    export_stdout = access_side.move(export_thread.stdtask.task.base)

    await import_thread.stdtask.unshare_files(going_to_exec=True)
    await import_thread.stdtask.stdin.replace_with(import_stdin)
    child_task = await import_thread.execve(dest_nix_bin/"nix-store", ["nix-store", "--import"])

    await export_thread.stdtask.unshare_files(going_to_exec=True)
    await export_thread.stdtask.stdout.replace_with(export_stdout)
    await export_thread.execve(dest_nix_bin/"nix-store", ["nix-store", "--export", *closure])
    await child_task.check()
    return dest_path

class NixPath(handle.Path):
    "A path in the Nix store, which can therefore be deployed to a remote host with Nix."
    @classmethod
    async def make(cls, thr: RAMThread, path: handle.Path) -> NixPath:
        return cls((await Path(thr, path).canonicalize()).handle)

    def __init__(self, *args) -> None:
        super().__init__(*args)
        root, nix, store = self.parts[:3]
        if root != b"/" or nix != b"nix" or store != b"store":
            raise Exception("path doesn't start with /nix/store")


import importlib.resources
import json

class StorePath:
    def __init__(self, path: handle.Path, closure: t.List[handle.Path]) -> None:
        self.path = path
        self.closure = closure

    @classmethod
    def _load_without_registering(self, name: str) -> StorePath:
        dep = nixdeps.import_nixdep('rsyscall._nixdeps', name)
        path = handle.Path(dep.path)
        closure = [handle.Path(elem) for elem in dep.closure]
        return StorePath(path, closure)

class Store:
    def __init__(self, stdtask: StandardTask, nix: StorePath) -> None:
        self.stdtask = stdtask
        self.nix = nix
        # cache the target path, mildly useful caching for the pointers
        self.roots: t.Dict[StorePath, Path] = {}
        self._add_root(nix, Path(self.stdtask.ramthr, nix.path))

    def _add_root(self, store_path: StorePath, path: Path) -> None:
        self.roots[store_path] = path

    async def create_root(self, store_path: StorePath, path: Path) -> Path:
        # TODO create a Nix temp root pointing to this path
        self._add_root(store_path, path)
        return path

    async def realise(self, store_path: StorePath) -> Path:
        if store_path in self.roots:
            return self.roots[store_path]
        path = Path(self.stdtask.ramthr, store_path.path)
        if await path.access(read=True):
            return (await self.create_root(store_path, path))
        raise NotImplementedError("TODO deploy this store_path from local_store")

    async def bin(self, store_path: StorePath, name: str) -> Command:
        path = await self.realise(store_path)
        return Command(path.handle/"bin"/name, [name], {})

nix = StorePath._load_without_registering("nix")
local_store = Store(local.stdtask, nix)

def import_nix_dep(name: str) -> StorePath:
    store_path = StorePath._load_without_registering(name)
    # the local store has a root for every StorePath; that's where the
    # paths actually originally are.
    local_store._add_root(store_path, Path(local_store.stdtask.ramthr, store_path.path))
    return store_path

rsyscall = import_nix_dep("rsyscall")
