"""A cool async REPL and astcodeop thing.

This lacks functionality equivalent to codeop.Compile or
codeop.CommandCompiler, because the AST object returned from
compile(ONLY_AST) doesn't expose the information to us about what
__future__ statements the compile process has seen. To properly
implement those classes, either the return value of compile(ONLY_AST)
needs to contain that information, or we need to reimplement the
simple __future__ statement scanner contained in the Python core.

"""
import typeguard
import ast
import typing as t
import codeop
import ast
import __future__
import types
import inspect
from dataclasses import dataclass

import trio
import abc

def _ast_compile(source, filename, symbol):
    return compile(source, filename, symbol, ast.PyCF_ONLY_AST|codeop.PyCF_DONT_IMPLY_DEDENT)

def ast_compile_command(source, filename="<input>", symbol="single"):
    """Like codeop.compile_command, but returns an AST instead.

    """
    return codeop._maybe_compile(_ast_compile, source, filename, symbol)

def ast_compile_interactive(source: str) -> t.Optional[ast.Interactive]:
    return codeop._maybe_compile(_ast_compile, source, "<input>", "single")

class IncrementalParser:
    def __init__(self) -> None:
        self.buf: str = ""

    def add(self, data: str) -> t.List[ast.Interactive]:
        ret = []
        for line in data.split('\n'):
            self.buf += line + '\n'
            astob = ast_compile_interactive(self.buf)
            if astob is not None:
                self.buf = ""
                ret.append(astob)
        return ret

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
        code.co_filename, 
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

def compile_to_awaitable(astob: ast.Interactive,
                         global_vars: t.Dict[str, t.Any]) -> t.Awaitable:
    """Compile this AST, which may contain await statements, to an awaitable.

    - If the AST calls return, then a value is returned from the awaitable.
    - If the AST raises an exception, then the awaitable raises that exception.
    - If the AST neither returns a value nor raises an exception, then _InternalResult is
      raised. 
    - If the last statement in the AST is an expression, then on the _InternalResult
      exception, is_expression is set and value contains the value of the expression.
    - If the last statement in the AST is not an expression, then on the _InternalResult
      exception, is_expression is False and value contains None.

    """
    wrapper_name = "__internal_async_wrapper__"
    wrapper = ast.parse(f"""
async def {wrapper_name}():
    try:
        pass
    finally:
        locals()
""", filename="<internal_wrapper>", mode="single")
    try_block = wrapper.body[0].body[0]
    try_block.body = astob.body
    if isinstance(try_block.body[-1], (ast.Expr, ast.Await)):
        # if the last statement in the AST is an expression, then have its value be
        # propagated up by throwing it from the _InternalResult exception.
        wrapper_raise = ast.parse("raise _InternalResult(True, None)", filename="<internal_wrapper>", mode="single").body[0]
        wrapper_raise.exc.args[1] = try_block.body[-1].value
        try_block.body[-1] = wrapper_raise
    else:
        wrapper_raise = ast.parse("raise _InternalResult(False, None)", filename="<internal_wrapper>", mode="single").body[0]
        try_block.body.append(wrapper_raise)
    global_vars.update({
        '__builtins__': __builtins__,
        '_InternalResult': _InternalResult,
    })
    exec(compile(wrapper, '<input>', 'single'), global_vars)
    func = global_vars[wrapper_name]
    del global_vars[wrapper_name]
    # don't create a new local variable scope
    func.__code__ = without_co_newlocals(func.__code__)
    return func()

class Result:
    pass

@dataclass
class ReturnResult(Result):
    value: t.Any

@dataclass
class ExceptionResult(Result):
    exception: BaseException

@dataclass
class ExpressionResult(Result):
    value: t.Any

@dataclass
class FallthroughResult(Result):
    pass

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
        return ExceptionResult(e)
    else:
        return ReturnResult(val)

class PureREPL:
    def __init__(self) -> None:
        self.parser = IncrementalParser()
        self.global_vars: t.Dict[str, t.Any] = {}

    async def add(self, data: str) -> t.List[Result]:
        ret = []
        for astob in self.parser.add(data):
            result = await eval_single(astob, self.global_vars)
            ret.append(result)
        return ret

# ok so now we just need to, um.
# are we gonna support a PS2?
# no ps2 is dumb
# we'll support a prompt and that's it
# okay! so! yeah!
# we'll just read from input,
# send it to add,
# and for each result we get back,
# print the result and '\n$ '
# oh hm.
# what about syntax errors?
# well, say we add something with a syntax error
# then I guess we'll get an error!
# argh, this is a good reason, I SUPPOSE, to have the line buffering done outside. hm.
# so, it's nice to have line buffering so that syntax errors in later lines don't prevent earlier lines from being run.
# but we also need to make sure to surface the results for those earlier lines even if later lines have syntax errors
# but we also need to actually deal with the whole thing
# urgh hmm
# the real python repl seems to continue processing after a syntax error. hmm.
# lol it's dumb, hm
# compile_command or whatever throws an error immediately on seeing raise return. hmm.
# so, I guess then, when we get a syntax error we want to flush the buffer,
# and then keep feeding lines.
# hmmmmmm
# so if I split it by line myself, then this works.
# but if I just send in raw data...
# then I get back a stream of...
# Results, and SyntaxErrors
# I guess that could be fine.
# ugh no there are other exceptions I can get too
# ideally then I'd get a stream of results and syntaxerrors, hm.
# maybe, I'd call add,
# then I'd call pump to get results until there's nothing left.
# hmm.
# we could character-buffer, but that would cause problems - we'd get incomplete expressions.
# users expect line-buffering.

# okay what if we internally handled the exception and printed it?
# blagh urgh ack
# okay what if we just cleared the buffer on exception and returned that exception up as part of the list?

# wait um, how do we know when to prompt for more?
# oh if we aren't line-buffering, we don't know how to
# ummmmmmmmm
class AsyncREPL:
    pass

async def repl(locals, request_message, wanted_type: t.Type) -> t.Any:
    await print(request_message)
    while True:
        try:
            ret = await read_and_evaluate()
        except ContinueRunning:
            pass
        except FromREPL as e:
            raise e.inner
        except:
            await print_exception()
        else:
            typeguard.check_type('return_value', ret, wanted_type)
            return ret

repl = PureREPL()
