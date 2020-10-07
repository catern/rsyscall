"Just the outcome library, with a little more typing"
from outcome import Value, Error
import outcome
import typing as t

__all__ = [
    'Outcome',
    'Value',
    'Error',
]

T = t.TypeVar('T')
class Outcome(t.Generic[T], outcome.Outcome):
    pass
