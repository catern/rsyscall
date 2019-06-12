from dataclasses import dataclass
from arepl.acompile import compile_to_awaitable, _InternalResult
import ast
import typing as t

class BaseResult:
    pass

@dataclass
class ReturnResult(BaseResult):
    value: t.Any

@dataclass
class ExceptionResult(BaseResult):
    exception: BaseException

@dataclass
class ExpressionResult(BaseResult):
    value: t.Any

@dataclass
class FallthroughResult(BaseResult):
    pass
if t.TYPE_CHECKING:
    Result = t.Union[ReturnResult, ExceptionResult, ExpressionResult, FallthroughResult]
else:
    # make isinstance checks actually work
    Result = BaseResult

async def eval_single(astob: ast.Interactive, global_vars: t.Dict[str, t.Any]) -> Result:
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
