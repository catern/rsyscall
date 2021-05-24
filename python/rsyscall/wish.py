"""Several REPL-based `wish.WishGranter`s for the `wish` library

This module provides several choices of `wish.WishGranter`s for the wish library. Each
`WishGranter` is an asynchronous REPL based on the `arepl` library.

In fact, this library automatically instantiates `ConsoleGenie` and sets
`wish.my_wish_granter` to it at import time. Not very nice, but convenient.

Also, for convenience, we re-export `wish.wish` and `wish.Wish`.

"""
from __future__ import annotations
from rsyscall.command import Command
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.thread import Thread
from rsyscall.path import Path
from wish import wish, WishGranter, Wish, my_wish_granter
import logging
import os
import arepl
import sys
import traceback
import trio
import typing as t

from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.wait import W
from rsyscall.unistd import Pipe

logger = logging.getLogger(__name__)

__all__ = [
    'ConsoleGenie',
    'ConsoleServerGenie',
    'run_repl',
    'serve_repls',
]

T = t.TypeVar('T')

class ConsoleGenie(WishGranter):
    "A WishGranter which satisfies wishes by starting a REPL on stdin/stdout for human intervention"
    @classmethod
    async def make(self, thread: Thread):
        "Create a ConsoleGenie that will serve using `thread`'s stdin/stdout"
        cat = await thread.environ.which("cat")
        return ConsoleGenie(thread, cat)

    def __init__(self, thread: Thread, cat: Command) -> None:
        self.thread = thread
        self.cat = cat
        self.lock = trio.Lock()

    async def wish(self, wish: Wish[T]) -> T:
        """Serve a REPL on stdin/stdout and returns the value returned from it; throws on REPL hangup

        We use cat as a hack to be async; we can't robustly turn stdin/stdout into
        AsyncFDs, because setting them to NONBLOCK will be inherited by other processes
        using the same terminal. Instead, we just start two cats to do blocking
        reads/writes of stdin/stdout, then do async reads/writes to the cats.

        """
        async with self.lock:
            message = "".join(traceback.format_exception(None, wish, wish.__traceback__))
            wisher_frame = [frame for (frame, lineno) in traceback.walk_tb(wish.__traceback__)][-1]

            to_term_pipe = await (await self.thread.task.pipe(await self.thread.ram.malloc(Pipe))).read()
            from_term_pipe = await (await self.thread.task.pipe(await self.thread.ram.malloc(Pipe))).read()
            async_from_term = await self.thread.make_afd(from_term_pipe.read, set_nonblock=True)
            async_to_term = await self.thread.make_afd(to_term_pipe.write, set_nonblock=True)
            try:
                cat_stdin_thread = await self.thread.clone()
                await cat_stdin_thread.task.inherit_fd(to_term_pipe.read).dup2(cat_stdin_thread.stdin)
                async with await cat_stdin_thread.exec(self.cat):
                    cat_stdout_thread = await self.thread.clone()
                    await cat_stdout_thread.task.inherit_fd(from_term_pipe.write).dup2(cat_stdout_thread.stdout)
                    async with await cat_stdout_thread.exec(self.cat):
                        ret = await run_repl(async_from_term, async_to_term, {
                            **wisher_frame.f_locals,
                            **wisher_frame.f_globals,
                            '__repl_stdin__': async_from_term,
                            '__repl_stdout__': async_to_term,
                            'wish': wish,
                            'wisher_frame': wisher_frame,
                        }, wish.return_type, message)
                        return ret
            finally:
                await async_from_term.close()
                await async_to_term.close()

class ConsoleServerGenie(WishGranter):
    """On wish, listens for connections to a socket in `sockdir`, and serves a REPL to them

    Also, immediately starts socat from `thread` connecting to the socket; that means a
    REPL is served on stdin/stdout.

    The socket names are generated from the function and line number at which wish was
    called. The sockets are unlinked after a value is returned from some REPL.

    Multiple connections to the socket are supported at a time. Once one returns a value,
    all are cancelled.

    """
    @classmethod
    async def make(self, thread: Thread, sockdir: Path):
        socat = await thread.environ.which("socat")
        return ConsoleServerGenie(thread, sockdir, socat)

    def __init__(self, thread: Thread, sockdir: Path, socat: Command) -> None:
        self.thread = thread
        self.sockdir = sockdir
        self.socat = socat
        self.name_counts: t.Dict[str, int] = {}

    def _uniquify_name(self, name: str) -> str:
        "We never reuse a name for a socket."
        if name not in self.name_counts:
            self.name_counts[name] = 1
            return name
        else:
            self.name_counts[name] += 1
            return name + f".{self.name_counts[name]}"

    async def wish(self, wish: Wish[T]) -> T:
        message = "".join(traceback.format_exception(None, wish, wish.__traceback__))
        wisher_frame = [frame for (frame, lineno) in traceback.walk_tb(wish.__traceback__)][-1]
        sock_name = self._uniquify_name(f'{wisher_frame.f_code.co_name}-{wisher_frame.f_lineno}')
        sock_path = self.sockdir/sock_name
        cmd = self.socat.args("-", "UNIX-CONNECT:" + os.fsdecode(sock_path))
        sockfd = await self.thread.make_afd(await self.thread.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK))
        await sockfd.bind(await self.thread.ptr(await SockaddrUn.from_path(self.thread, sock_path)))
        await sockfd.handle.listen(10)
        async with trio.open_nursery() as nursery:
            @nursery.start_soon
            async def do_socat():
                while True:
                    thread = await self.thread.clone()
                    try:
                        child = await thread.exec(cmd)
                    except:
                        await thread.exit(0)
                        raise
                    async with child:
                        await child.waitpid(W.EXITED)
            ret = await serve_repls(sockfd, {
                **wisher_frame.f_locals,
                **wisher_frame.f_globals,
                'wisher_frame': wisher_frame,
            }, wish.return_type, message)
            nursery.cancel_scope.cancel()
        await self.thread.task.unlink(await self.thread.ram.ptr(sock_path))
        return ret

async def run_repl(infd: AsyncFileDescriptor,
                   outfd: AsyncFileDescriptor,
                   global_vars: t.Dict[str, t.Any],
                   wanted_type: t.Type[T], message: str) -> T:
    """Serve a REPL on infd/outfd, guarding that it only returns `wanted_type`

    We print `message` on startup.  `global_vars` is mutably used as the global variables
    dict for the REPL.

    """
    async with trio.open_nursery() as repl_nursery:
        @repl_nursery.start_soon
        async def wait_for_rdhup() -> None:
            await infd.wait_for_rdhup()
            # when we get RDHUP on the connection, we want to cancel the REPL, even if
            # some task is in progress.
            raise Exception("REPL connection hangup")
        await outfd.write_all_bytes((message+"\n").encode())
        ret = await arepl.run_repl(infd.read_some_bytes, outfd.write_all_bytes, global_vars, wanted_type)
        repl_nursery.cancel_scope.cancel()
    return ret

async def serve_repls(listenfd: AsyncFileDescriptor,
                      initial_vars: t.Dict[str, t.Any],
                      wanted_type: t.Type[T], message: str) -> T:
    """Serve REPLs on a socket until someone gives us the type we want

    Multiple connections to the socket can be active simultaneously, with REPLs being
    served to all.

    Each REPL has a reference to the REPL variables of all other REPLs, through the
    __repls__ variable present in each REPL.

    A good extension would be to support killing a REPL from another REPL. We didn't do
    that for some reason, not sure why.

    """
    repl_vars: t.Dict[str, t.Dict[str, t.Any]] = {}
    retval = None
    async with trio.open_nursery() as nursery:
        async def do_repl(connfd: AsyncFileDescriptor,
                          global_vars: t.Dict[str, t.Any]) -> None:
            try:
                ret = await run_repl(connfd, connfd, global_vars, wanted_type, message)
            except arepl.FromREPL as e:
                raise e.exn from e
            except Exception:
                logger.exception("run_repl's internal logic raised an exception, disconnecting that REPL and continuing")
            else:
                nonlocal retval
                retval = ret
                nursery.cancel_scope.cancel()
            finally:
                await connfd.close()
        num = 0
        while True:
            connfd = await listenfd.make_new_afd(await listenfd.accept(SOCK.NONBLOCK))
            global_vars = {**initial_vars,
                           '__repls__': repl_vars,
                           '__repl_stdin__': connfd,
                           '__repl_stdout__': connfd}
            repl_vars[str(num)] = global_vars
            nursery.start_soon(do_repl, connfd, global_vars)
            num += 1
    return retval

def _initialize_module() -> None:
    from rsyscall import local_thread
    my_wish_granter.set(trio.run(ConsoleGenie.make, local_thread))
_initialize_module()
