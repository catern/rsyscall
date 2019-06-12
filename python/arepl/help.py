import typing as t
import pydoc # type: ignore

class Output:
  def __init__(self) -> None:
    self.results: t.List[str] = []

  def write(self, s):
    self.results.append(s)

def help_to_str(request) -> str:
    out = Output()
    pydoc.Helper(None, out).help(request) # type: ignore
    return "".join(out.results)
