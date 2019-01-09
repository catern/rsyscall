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

import trio

def _ast_compile(source, filename, symbol):
    return compile(source, filename, symbol, ast.PyCF_ONLY_AST|codeop.PyCF_DONT_IMPLY_DEDENT)

def ast_compile_command(source, filename="<input>", symbol="single"):
    """Like codeop.compile_command, but returns an AST instead.

    """
    return codeop._maybe_compile(_ast_compile, source, filename, symbol)

def ast_compile_interactive(source: str) -> t.Optional[ast.Interactive]:
    return codeop._maybe_compile(_ast_compile, source, "<input>", "single")

class _InternalContinueRunning(Exception):
    pass

_wrapper_name = "__internal_async_wrapper__"
_wrapper = ast.parse(f"""
async def {_wrapper_name}(__local_vars__):
    locals().update(__local_vars__)
    try:
        pass
    finally:
        __local_vars__.update(locals())
    raise _InternalContinueRunning
""", filename="<internal_wrapper>", mode="single")

def compile_to_async_def(astob: ast.Interactive) -> t.Callable[[t.Dict[str, t.Any]], t.Awaitable]:
    """Compile this AST, wrapping it in an async function so that it may contain await statements

    The returned async function takes a dictionary to use as its
    locals, which it updates at the end of the function.

    The async function also raises _InternalContinueRunning at the
    end, so that calling code can tell if the wrapped code returned.

    """
    # replace the body of the try in the wrapper with the passed-in ast object's body
    _wrapper.body[0].body[1].body = astob.body
    local_vars = {}
    exec(compile(_wrapper, '<input>', 'single'), {
        '__builtins__': __builtins__,
        '_InternalContinueRunning': _InternalContinueRunning,
    }, local_vars)
    return local_vars[_wrapper_name]

async def read_and_evaluate(source: str, local_vars={}) -> t.Optional[t.Any]:
    astob = ast_compile_interactive(source)
    if astob is None:
        raise Exception("incomplete!")
    afunc = compile_to_async_def(astob)
    return (await afunc(local_vars))

class PureREPL:
    def add_input(self, data: bytes) -> t.Optional[bytes]:
        pass

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
