"""A pure asynchronous REPL, capable of parsing and running async code given as input

PureREPL is a basic async REPL. It's pure in the sense that it doesn't itself read input;
the user must pass input to it as strings.

"""
from dataclasses import dataclass
import ast
import traceback
import typeguard
import typing as t
from arepl.astcodeop import ast_compile_interactive
from arepl.aeval import (
    ReturnResult, ExceptionResult, ExpressionResult, FallthroughResult, Result, eval_single,
)
from arepl.help import help_to_str

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
            # remove the last newline
            astob = ast_compile_interactive(self.buf[:-1])
        except Exception:
            self.buf = ""
            raise
        else:
            if astob is not None:
                self.buf = ""
                return (await self.eval_single(astob))
            return None

class LineBuffer:
    "A simple character buffer to split data into lines"
    def __init__(self) -> None:
        self.buf: str = ""

    def add(self, data: str) -> t.List[str]:
        self.buf += data
        *lines, self.buf = self.buf.split('\n')
        return [line + '\n' for line in lines]

# TODO I should also be able to pass in a predicate function which I call on the return value.
# That way I can represent constraints on the returned value at a value level.
# (I still do the wanted_type so that mypy type checking is correct)
T = t.TypeVar('T')
async def run_repl(read: t.Callable[[], t.Awaitable[bytes]],
                   write: t.Callable[[bytes], t.Awaitable[None]],
                   global_vars: t.Dict[str, t.Any], wanted_type: t.Type[T]) -> T:
    async def print_to_user(*args) -> None:
        await write((" ".join([str(arg) for arg in args]) + "\n").encode())
    async def help_to_user(request) -> None:
        await write(help_to_str(request).encode())
    async def print_exn(e: BaseException) -> None:
        # this call to run_repl may take place at a time where an exception is being handled; when
        # we print this internal exception, we don't want to print that outside exception context,
        # since it's irrelevant.
        e.__suppress_context__ = True # type: ignore
        await write("".join(traceback.format_exception(None, e, e.__traceback__)).encode())
    global_vars['print'] = print_to_user
    global_vars['help'] = help_to_user
    repl = PureREPL(global_vars)
    line_buf = LineBuffer()
    await write(b">")
    while True:
        raw_data = await read()
        if len(raw_data) == 0:
            raise Exception("REPL hangup")
        for line in line_buf.add(raw_data.decode()):
            try:
                result = await repl.add_line(line)
            except Exception as exn:
                await print_exn(exn)
                continue
            if result is None:
                continue
            if isinstance(result, ReturnResult):
                try:
                    typeguard.check_type('return value', result.value, wanted_type)
                except TypeError as e:
                    await print_exn(e)
                else:
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
            await write(b">")
