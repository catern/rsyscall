import importlib.resources
from dataclasses import dataclass
from pathlib import Path
import typing as t
import json

@dataclass
class Nixdep:
    path: Path
    closure: t.List[Path]

_imported_nixdeps: t.Dict[t.Tuple[str, str], Nixdep] = {}

def import_nixdep(module: str, name: str) -> Nixdep:
    if (module, name) in _imported_nixdeps:
        return _imported_nixdeps[(module, name)]
    text = importlib.resources.read_text(module, name + '.json')
    data = json.loads(text)
    path = Path(data["path"])
    closure = [Path(elem) for elem in data["closure"]]
    nixdep = Nixdep(path, closure)
    _imported_nixdeps[(module, name)] = nixdep
    return nixdep
