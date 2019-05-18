import unittest
from arepl import *
import typing as t

T = t.TypeVar('T')
def await_pure(awaitable: t.Awaitable[T]) -> T:
    iterable = awaitable.__await__()
    try:
        next(iterable)
    except StopIteration as e:
        return e.value
    else:
        raise Exception("this awaitable actually is impure! it yields!")

class TestPure(unittest.TestCase):
    def test_add(self) -> None:
        async def test() -> None:
            repl = PureREPL({})
            async def eval(line: str) -> t.Any:
                result = await repl.add_line(line + '\n')
                if isinstance(result, ExpressionResult):
                    return result.value
                else:
                    raise Exception("unexpected", result)
            self.assertEqual(await eval('1'), 1)
            self.assertEqual(await eval('1+1'), 2)
            await repl.add_line('foo = 1\n')
            self.assertEqual(await eval('foo*4'), 4)
        await_pure(test())
