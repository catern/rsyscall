"""Convert `help()` output to a string.

`help()` usually sends its output to stdout, which might not be where
we want to write it, if our REPL is targeted somewhere else...

"""

import typing as t
import pydoc # type: ignore

__all__ = [
  'help_to_str',
]

class Output:
  def __init__(self) -> None:
    self.results: t.List[str] = []

  def write(self, s):
    self.results.append(s)

def help_to_str(request: t.Any) -> str:
    "Call `help` on `result`, and return the result as a string"
    out = Output()
    pydoc.Helper(None, out).help(request) # type: ignore
    return "".join(out.results)
