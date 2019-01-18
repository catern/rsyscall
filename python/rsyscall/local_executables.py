import importlib.resources
import trio
import typing as t
import json
from rsyscall.io import which, local_stdtask, SSHCommand, Command

try:
    executable_paths_file = importlib.resources.open_binary('rsyscall', 'excutable_paths.json')
except FileNotFoundError:
    def find_command(name: str) -> Command:
        return trio.run(which, local_stdtask, name)
    tar = find_command('tar')
    cat = find_command('cat')
    ssh = SSHCommand.make(find_command('ssh').executable_path)
    nix_daemon = find_command('nix-daemon')
    nix_store = find_command('nix-store')
else:
    executable_paths: t.Dict[str, str] = json.load(executable_paths_file)
    def make_command(name: str) -> Command:
        path = local_stdtask.task.base.make_path_from_bytes(executable_paths[name].encode())
        return Command(path, [name.encode()], {})
    tar = make_command('tar')
    cat = make_command('cat')
    ssh = SSHCommand.make(make_command('ssh').executable_path)
    nix_daemon = make_command('nix-daemon')
    nix_store = make_command('nix-store')
