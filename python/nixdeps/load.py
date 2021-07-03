"The runtime functionality to actually use Nix dependencies"
from dataclasses import dataclass
from pathlib import Path
import typing as t

__all__ = [
    'PackageClosure',
]

@dataclass
class PackageClosure:
    path: Path
    closure: t.List[str]
