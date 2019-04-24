import importlib.resources
from dataclasses import dataclass
from pathlib import Path
import typing as t
import json

@dataclass
class Nixdep:
    path: Path
    closure: t.List[Path]

def import_nixdep(module: str, name: str) -> None:
    text = importlib.resources.read_text(module, name + '.json')
    data = json.loads(text)
    path = Path(data["path"])
    closure = [Path(elem) for elem in data["closure"]]
    return Nixdep(path, closure)
    
