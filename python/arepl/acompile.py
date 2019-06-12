"""Async equivalent of compile, which takes an AST and returns an awaitable

"""
from dataclasses import dataclass
import ast
import builtins
import types
import inspect
import typing as t

def without_co_newlocals(code: types.CodeType) -> types.CodeType:
    """Return a copy of this code object with the CO_NEWLOCALS flag unset.

    This code object, when executed, will not create a new scope; this is useful for
    functions running in REPLs, I suppose.

    """
    return types.CodeType(
        code.co_argcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags & ~inspect.CO_NEWLOCALS,
        code.co_code,
        code.co_consts,
        code.co_names,
        code.co_varnames,
        code.co_filename if code.co_filename is not None else "<without_co_newlocals>",
        code.co_name,
        code.co_firstlineno,
        code.co_lnotab,
        code.co_freevars,
        code.co_cellvars
    )

@dataclass
class _InternalResult(Exception):
    is_expression: bool
    value: t.Any

__result_exception__ = _InternalResult

def compile_to_awaitable(astob: ast.Interactive,
                         global_vars: t.Dict[str, t.Any]) -> t.Awaitable:
    """Compile this AST, which may contain await statements, to an awaitable.

    - If the AST calls return, then a value is returned from the awaitable.
    - If the AST raises an exception, then the awaitable raises that exception.
    - If the AST neither returns a value nor raises an exception, then __result_exception__ is
      raised.
    - If the last statement in the AST is an expression, then on the __result_exception__
      exception, is_expression is set and value contains the value of the expression.
    - If the last statement in the AST is not an expression, then on the __result_exception__
      exception, is_expression is False and value contains None.

    """
    wrapper_name = "__toplevel__"
    # we rely on the user not messing with __builtins__ in the REPL; that's something you
    # really aren't supposed to do, so I think that's fine.
    wrapper = ast.parse(f"""
async def {wrapper_name}():
    try:
        pass
    finally:
        __builtins__.locals()
""", filename="<internal_wrapper>", mode="single")
    try_block = wrapper.body[0].body[0] # type: ignore
    try_block.body = astob.body
    if isinstance(try_block.body[-1], (ast.Expr, ast.Await)):
        # if the last statement in the AST is an expression, then have its value be
        # propagated up by throwing it from the __result_exception__ exception.
        wrapper_raise = ast.parse("raise __result_exception__(True, None)", filename="<internal_wrapper>", mode="single").body[0] # type: ignore
        wrapper_raise.exc.args[1] = try_block.body[-1].value # type: ignore
        try_block.body[-1] = wrapper_raise
    else:
        wrapper_raise = ast.parse("raise __result_exception__(False, None)", filename="<internal_wrapper>", mode="single").body[0] # type: ignore
        try_block.body.append(wrapper_raise)
    global_vars.update({
        '__builtins__': builtins,
        '__result_exception__': __result_exception__,
    })
    exec(compile(wrapper, '<input>', 'single'), global_vars)
    func = global_vars[wrapper_name]
    del global_vars[wrapper_name]
    # don't create a new local variable scope
    func.__code__ = without_co_newlocals(func.__code__)
    return func()
