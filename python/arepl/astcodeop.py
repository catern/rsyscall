"""Like the stdlib codeop module, but returning an AST instead.

This is useful because we can properly deal with `await`s at the AST level.

We lack functionality precisely equivalent to `codeop.Compile` or `codeop.CommandCompiler`,
because the AST object returned from `compile(ONLY_AST)` doesn't expose the information to
us about what `__future__` statements the compile process has seen. To properly implement
those classes, either the return value of `compile(ONLY_AST)` needs to contain that
information, or we need to reimplement the simple `__future__` statement scanner contained
in the Python core.

"""
import codeop
import ast
import typing as t

def _ast_compile(source, filename, symbol) -> t.Any:
    PyCF_DONT_IMPLY_DEDENT = codeop.PyCF_DONT_IMPLY_DEDENT # type: ignore
    return compile(source, filename, symbol, ast.PyCF_ONLY_AST|PyCF_DONT_IMPLY_DEDENT)

def ast_compile_command(source: str, filename="<input>", symbol="single") -> t.Any:
    "Like codeop.compile_command, but returns an AST instead."
    _maybe_compile = codeop._maybe_compile # type: ignore
    return _maybe_compile(_ast_compile, source, filename, symbol)

def ast_compile_interactive(source: str) -> t.Optional[ast.Interactive]:
    "Compiles this single interactive statement into an AST"
    return ast_compile_command(source, "<input>", "single")
