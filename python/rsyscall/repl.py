import typeguard
import ast
import typing as t
import codeop

def compile_await(self):
    pass

def maybe_compile(source, filename="<input>", symbol="single") -> t.Any:
    comp = codeop.CommandCompiler()
    comp.compiler = None

class ASTCompile:
    """Instances of this class behave much like the built-in compile
    function, but if one is used to compile text containing a future
    statement, it "remembers" and compiles all subsequent program texts
    with the statement in force."""
    def __init__(self):
        self.flags = PyCF_DONT_IMPLY_DEDENT

    def __call__(self, source, filename, symbol):
        codeob = compile(source, filename, symbol, self.flags, 1)
        for feature in _features:
            if codeob.co_flags & feature.compiler_flag:
                self.flags |= feature.compiler_flag
        return codeob

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
