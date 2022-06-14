import unittest
from arepl import *
import typing as t
import arepl.aeval
import arepl.astcodeop

T = t.TypeVar('T')
def await_pure(awaitable: t.Awaitable[T]) -> T:
    iterable = awaitable.__await__()
    try:
        next(iterable)
    except StopIteration as e:
        return e.value
    else:
        raise Exception("this awaitable actually is impure! it yields!")

async def anoop() -> None:
    return None

class TestPure(unittest.TestCase):
    def test_add(self) -> None:
        async def test() -> None:
            repl = PureREPL({'anoop': anoop})
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
            self.assertEqual(await eval('await anoop()'), None)
        await_pure(test())

    def test_newlocals(self) -> None:
        astob = arepl.astcodeop.ast_compile_interactive("foo = 42")
        global_vars = {}
        await_pure(arepl.aeval.eval_single(astob, global_vars))
        self.assertEqual(global_vars['foo'], 42)
