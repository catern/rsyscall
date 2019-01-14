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
import traceback
import ast
import typing as t
import codeop
import ast
import __future__
import types
import inspect
import builtins
from dataclasses import dataclass

import trio
import abc

def _ast_compile(source, filename, symbol):
    return compile(source, filename, symbol, ast.PyCF_ONLY_AST|codeop.PyCF_DONT_IMPLY_DEDENT) # type: ignore

def ast_compile_command(source: str, filename="<input>", symbol="single"):
    """Like codeop.compile_command, but returns an AST instead.

    """
    return codeop._maybe_compile(_ast_compile, source, filename, symbol) # type: ignore

def ast_compile_interactive(source: str) -> t.Optional[ast.Interactive]:
    return ast_compile_command(source, "<input>", "single")

class LineBuffer:
    def __init__(self) -> None:
        self.buf: str = ""

    def add(self, data: str) -> t.List[str]:
        self.buf += data
        *lines, self.buf = data.split('\n')
        return [line + '\n' for line in lines]

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
        # propagated up by throwing it from the __result_exception__ exception.
        wrapper_raise = ast.parse("raise __result_exception__(True, None)", filename="<internal_wrapper>", mode="single").body[0]
        wrapper_raise.exc.args[1] = try_block.body[-1].value # type: ignore
        try_block.body[-1] = wrapper_raise
    else:
        wrapper_raise = ast.parse("raise __result_exception__(False, None)", filename="<internal_wrapper>", mode="single").body[0]
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
    except __result_exception__ as e:
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
        self.global_vars = global_vars
        self.buf = ""

    async def eval_single(self, astob: ast.Interactive) -> Result:
        return (await eval_single(astob, self.global_vars))

    async def add_line(self, data: str) -> t.Optional[Result]:
        """Add a single line to the REPL buffer and try to parse and evaluate the AST.

        If no AST can be parsed from the buffer, returns None.
        
        Make sure to pass exactly one single line to this function,
        including newline! Otherwise, you might pass multiple
        statements at once, and the parser won't like that.

        """
        self.buf += data
        try:
            astob = ast_compile_interactive(self.buf)
        except Exception:
            self.buf = ""
            raise
        else:
            if astob is not None:
                self.buf = ""
                return (await self.eval_single(astob))
            return None

T = t.TypeVar('T')
def await_pure(awaitable: t.Awaitable[T]) -> T:
    iterable = awaitable.__await__()
    try:
        next(iterable)
    except StopIteration as e:
        return e.value
    else:
        raise Exception("this awaitable actually is impure! it yields!")

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

import pydoc
class Output:
  def __init__(self) -> None:
    self.results: t.List[str] = []

  def write(self, s):
    self.results.append(s)

def help_to_str(request) -> str:
    out = Output()
    pydoc.Helper(None, out).help(request)
    return "".join(out.results)

async def run_repl(read: t.Callable[[], t.Awaitable[bytes]],
                   write: t.Callable[[bytes], t.Awaitable[None]],
                   global_vars: t.Dict[str, t.Any], wanted_type: t.Type[T]) -> T:
    async def print_to_user(*args):
        await write((" ".join([str(arg) for arg in args]) + "\n").encode())
    async def help_to_user(request):
        await write(help_to_str(request).encode())
    async def print_exn(e: BaseException):
        await write("".join(traceback.format_exception(None, e, e.__traceback__)).encode())
    global_vars['print'] = print_to_user
    global_vars['help'] = help_to_user
    repl = PureREPL(global_vars)
    buf = LineBuffer()
    line_queue: trio.Queue[str] = trio.Queue(999)
    async with trio.open_nursery() as nursery:
        @nursery.start_soon
        async def do_reading() -> None:
            while True:
                raw_data = await read()
                # when we get EOF on the connection, we want to cancel the
                # REPL, even if some task is in progress.
                if len(raw_data) == 0:
                    raise Exception("REPL hangup")
                data = raw_data.decode()
                for line in buf.add(data):
                    line_queue.put_nowait(line)
        while True:
            await write(b">")
            line = await line_queue.get()
            try:
                result = await repl.add_line(line)
            except Exception as exn:
                await print_exn(exn)
                continue
            if result is None:
                pass
            elif isinstance(result, ReturnResult):
                try:
                    typeguard.check_type('return value', result.value, wanted_type)
                except TypeError as e:
                    await print_exn(e)
                else:
                    nursery.cancel_scope.cancel()
                    return result.value
            elif isinstance(result, ExceptionResult):
                if isinstance(result.exception, FromREPL):
                    raise result.exception
                else:
                    await print_exn(result.exception)
            elif isinstance(result, ExpressionResult):
                await print_to_user(result.value)
                global_vars['_'] = result.value
            elif isinstance(result, FallthroughResult):
                pass
            else:
                raise Exception("bad Result returned from PureREPL", result)

repl = PureREPL({})
