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
    return compile(source, filename, symbol, ast.PyCF_ONLY_AST|codeop.PyCF_DONT_IMPLY_DEDENT) # type: ignore

def ast_compile_command(source, filename="<input>", symbol="single"):
    """Like codeop.compile_command, but returns an AST instead.

    """
    return codeop._maybe_compile(_ast_compile, source, filename, symbol) # type: ignore

def ast_compile_interactive(source: str) -> t.Optional[ast.Interactive]:
    return ast_compile_command(_ast_compile, "<input>", "single")

class IncrementalParser:
    def __init__(self) -> None:
        self.buf: str = ""

    def add(self, data: str) -> t.List[t.Union[ast.Interactive, Exception]]:
        ret: t.List[t.Union[ast.Interactive, Exception]] = []
        for line in data.split('\n'):
            self.buf += line + '\n'
            try:
                astob = ast_compile_interactive(self.buf)
            except Exception as e:
                self.buf = ""
                ret.append(e)
            else:
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
    try_block = wrapper.body[0].body[0] # type: ignore
    try_block.body = astob.body
    if isinstance(try_block.body[-1], (ast.Expr, ast.Await)):
        # if the last statement in the AST is an expression, then have its value be
        # propagated up by throwing it from the _InternalResult exception.
        wrapper_raise = ast.parse("raise _InternalResult(True, None)", filename="<internal_wrapper>", mode="single").body[0]
        wrapper_raise.exc.args[1] = try_block.body[-1].value # type: ignore
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

class FromREPL(Exception):
    def __init__(self, exn: Exception) -> None:
        self.exn = exn

class PureREPL:
    def __init__(self, global_vars: t.Dict[str, t.Any]) -> None:
        self.parser = IncrementalParser()
        self.global_vars = global_vars

    async def add(self, data: str) -> t.List[t.Union[Result, Exception]]:
        """Add some data to the REPL buffer and evaluate the ASTs parsed from it.

        Returns a list containing a Result for each time we were able to parse out and
        evaluate an AST, and an Exception for each time we had a SyntaxError or other
        issue.

        """
        ret: t.List[t.Union[Result, Exception]] = []
        for ast_or_exn in self.parser.add(data):
            if isinstance(ast_or_exn, Exception):
                ret.append(ast_or_exn)
            elif isinstance(ast_or_exn, ast.Interactive):
                try:
                    result = await eval_single(ast_or_exn, self.global_vars)
                except Exception as e:
                    ret.append(e)
                else:
                    ret.append(result)
            else:
                raise Exception("bad value returned from parser", ast_or_exn)
        return ret

    async def run(read: t.Callable[[], t.Awaitable[bytes]],
                  write: t.Callable[[bytes], t.Awaitable[None]],
                  wanted_type: t.Type[T]) -> T:
        async def print(*args):
            await write(" ".join([str(arg) for arg in args]).encode())
        repl = PureREPL()
        repl.global_vars.update({'print':print, **initial_vars})
        while True:
            raw_data = await read()
            data = raw_data.decode()
            for result_or_exn in await repl.add(data):
                if isinstance(result_or_exn, Result):
                    result = result_or_exn
                    if isinstance(result, ReturnResult):
                        try:
                            typeguard.check_type('return value', result.value, wanted_type)
                        except TypeError as e:
                            await print(e)
                        else:
                            return result.value
                    elif isinstance(result, ExceptionResult):
                        if isinstance(result.exception, FromREPL):
                            raise result.exception.exn
                        else:
                            await print(result.exception)
                    elif isinstance(result, ExpressionResult):
                        await print(result.value)
                        repl.global_vars['_'] = result.value
                    elif isinstance(result, FallthroughResult):
                        pass
                    else:
                        raise Exception("bad Result returned from PureREPL", result)
                elif isinstance(result_or_exn, Exception):
                    await print(result_or_exn)

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
# Results, and Exceptions
# ok so we just: read from input,
# send it to add,
# and for each result or syntax error we get back,
# print the result or syntax error, and '\n$'.

T = t.TypeVar('T')
async def run_repl(read: t.Callable[[], t.Awaitable[bytes]],
                   write: t.Callable[[bytes], t.Awaitable[None]],
                   global_vars: t.Dict[str, t.Any], wanted_type: t.Type[T]) -> T:
    async def print(*args):
        await write(" ".join([str(arg) for arg in args]).encode())
    global_vars['print'] = print
    repl = PureREPL(global_vars)
    while True:
        raw_data = await read()
        data = raw_data.decode()
        # so maybe we can have a nursery which has a loop constantly calling read?
        # and it sends us the data?
        # and if we get an exception, it cancels us?
        # hmm it might be nice if the REPL just had all the data ready in it.
        # and we just 
        results = await repl.add(data)
        for result_or_exn in results:
            if isinstance(result_or_exn, Result):
                result = result_or_exn
                if isinstance(result, ReturnResult):
                    try:
                        typeguard.check_type('return value', result.value, wanted_type)
                    except TypeError as e:
                        await print(e)
                    else:
                        return result.value
                elif isinstance(result, ExceptionResult):
                    if isinstance(result.exception, FromREPL):
                        raise result.exception
                    else:
                        await print(result.exception)
                elif isinstance(result, ExpressionResult):
                    await print(result.value)
                    global_vars['_'] = result.value
                elif isinstance(result, FallthroughResult):
                    pass
                else:
                    raise Exception("bad Result returned from PureREPL", result)
            elif isinstance(result_or_exn, Exception):
                await print(result_or_exn)

repl = PureREPL()
