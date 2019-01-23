import importlib.resources
import trio
import typing as t
import json
from rsyscall.io import which, local_stdtask, SSHCommand, Command, NixPath

try:
    executable_paths_file = importlib.resources.open_binary('rsyscall', 'excutable_paths.json')
except FileNotFoundError:
    def make_command(name: str) -> Command:
        cmd = trio.run(which, local_stdtask, name)
        path = cmd.executable_path
        nix_path = trio.run(NixPath.make, local_stdtask.task, path)
        return Command(nix_path, [name.encode()], {})
else:
    executable_paths: t.Dict[str, str] = json.load(executable_paths_file)
    def make_command(name: str) -> Command:
        path = local_stdtask.task.base.make_path_from_bytes(executable_paths[name].encode())
        nix_path = NixPath(path.base, path.components)
        return Command(nix_path, [name.encode()], {})

tar = make_command('tar')
cat = make_command('cat')
ssh = SSHCommand.make(make_command('ssh').executable_path)
nix_daemon = make_command('nix-daemon')
nix_store = make_command('nix-store')
