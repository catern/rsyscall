"An async-supporting equivalent of eval(..., 'single')"
from dataclasses import dataclass
from arepl.acompile import compile_to_awaitable, _InternalResult
import ast
import typing as t

class Result:
    pass

@dataclass
class ReturnResult(Result):
    "The statement returned a value."
    value: t.Any

@dataclass
class ExceptionResult(Result):
    "The statement raised an exception."
    exception: BaseException

@dataclass
class ExpressionResult(Result):
    "The statement was actually an expression, and evaluated to a value."
    value: t.Any

@dataclass
class FallthroughResult(Result):
    "The statement was an assignment, or pass, or something, and we've fallen through, with nothing to print."
    pass

async def eval_single(astob: ast.Interactive, global_vars: t.Dict[str, t.Any]) -> Result:
    "Compile and evaluate this snippet of AST, with these globals, and return its result"
    awaitable = compile_to_awaitable(astob, global_vars)
    try:
        val = await awaitable
    except _InternalResult as e:
        if e.is_expression:
            return ExpressionResult(e.value)
        else:
            return FallthroughResult()
    except BaseException as e:
        # We want to skip the innermost frame of the traceback, which shows "await awaitable".
        e.__traceback__ = e.__traceback__.tb_next # type: ignore
        return ExceptionResult(e)
    else:
        return ReturnResult(val)
