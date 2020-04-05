"""A typed API for generically prompting the user for a typed value, typically by dropping to a REPL

The metaphor we use is "wishing" for a value of some type, and then getting back a value
of that type. We use the wish function and the Wish class to do this. We follow many
patterns of exception handling, so `wish` can be thought of as a version of `raise` which
returns a value, and `Wish` can be thought of as an Exception object; indeed, it inherits
from Exception. Like `raise` and exception handlers, `wish` will always invoke the closest
bound wish handler.

The `wish` API is sufficiently general to cover a variety of different uses. Most
basically, it can be used to drop to a REPL at any time so that the user may interact with
the program. Since `wish` is async, this can be used even in running applications without
disturbing the rest of the application, unlike alternatives like `breakpoint`.

Another application is repairing broken systems. We can model "repair" of a broken system
as wishing for a fixed version of a broken value, which will be interactively corrected by
the user. If we make such a wish, we might want the code calling wish to perform
additional automated checks on the returned value, and wish again if the checks fail.

Yet another application is simple prompting of the user for values we cannot produce
programmatically, or prompting for the user to take actions we cannot perform
programmatically. We might prompt the user for some difficult-to-encode information about
the state of the world. Or we might prompt the user to perform some action manually that
is difficult for us to do automatically. Because `wish` invokes a wish handler, we can
automate these actions after the fact, and modify our automation to our needs, without
changing the module that calls `wish`.

To wish for a value, we create a value of class Wish, which should contain the type object
that we're wishing for, and pass it to the wish function. wish will capture a traceback of
our stack, attach it to the Wish, present that Wish to the user, and return the value
returned by the user.

When we wish for a value, we invoke the closest bound WishGranter; that handles prompting
the user and providing some UI for the user to produce the value. The WishGranter may
choose to typecheck the value returned by the user to ensure that it matches the value
requested in the Wish.  If the WishGranter provides a REPL, it may want to extract local
variables from the traceback captured by wish, and present them to the user. If no
WishGranter is bound, we simply raise the Wish as an exception.

This library provides only console REPL WishGranters, but the API is entirely extensible,
so other ways to present a REPL, or even entirely different UIs, are possible. For
example, a REPL might be presented with a web UI; perhaps even a Jupyter notebook.

A WishGranter might also be entirely or partially automatic; it could respond to different
types of Wishes automatically, based on the type wished for, the subclass of Wish used,
the message, or other attributes, and propagate other wishes up to the WishGranter bound
above it.

"""
from __future__ import annotations
from contextvars import ContextVar
from rsyscall.command import Command
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.thread import Thread
from rsyscall.path import Path
import abc
import inspect
import logging
import os
import arepl
import sys
import traceback
import trio
import types
import typing as t

from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, AF
from rsyscall.sys.un import SockaddrUn
from rsyscall.sys.wait import W
from rsyscall.unistd import Pipe

logger = logging.getLogger(__name__)

__all__ = [
    'Wish',
    'WishGranter',
    'ConsoleGenie',
    'wish',
    'run_repl',
    'serve_repls',
]

# TODO should we inherit from BaseException or Exception?
T = t.TypeVar('T')
class Wish(BaseException, t.Generic[T]):
    """A request for a value of type `return_type`

    We inherit from BaseException. When wish is called on this value, it will fill in the
    exception fields on this value, in the same way that raise would fill in the exception
    fields of any exception.

    A user can further inherit from this class to add more information to the Wish, in the
    same way one would inherit from Exception to create a more specific Exception.

    """
    return_type: t.Type[T]

    def __init__(self, return_type: t.Type[T], *args) -> None:
        self.return_type = return_type
        super().__init__(*args)

my_wish_granter: ContextVar[WishGranter] = ContextVar('my_wish_granter')
class WishGranter:
    """An object capable of responding to a wish.

    A WishGranter is not active until it is bound. When wish is called, the closest bound
    WishGranter is used to satisfy the wish. The WishGranter may itself choose to call
    wish and propagate the wish up the stack. For example, a partially automated
    WishGranter might be able to handle only certain classes of Wish, and fall back to
    wishing again when it sees other classes.

    WishGranters are bound to my_wish_granter to become active. This merely means they
    will be used by `wish`; no actual change occurs to the WishGranter object.

    Since my_wish_granter is a ContextVar, it's useful to make an analogy to exception
    handlers, because the resolution process for ContextVars, and therefore WishGranters,
    works the same way.

    """
    @abc.abstractmethod
    async def wish(self, wish: Wish[T]) -> T:
        "Satisfy this wish, returning a value of the type requested by the wish"
        pass

def _frames_to_traceback(frames: t.List[types.FrameType]) -> t.Optional[types.TracebackType]:
    "Translate a list of frames (which can be obtained from the inspect module) to a traceback"
    tb = None
    for frame in frames:
        tb = types.TracebackType(tb, frame, frame.f_lasti, frame.f_lineno)
    return tb

# TODO should switch bool to typing_extensions.Literal[False]
async def wish(wish: Wish[T], *, from_exn: t.Union[BaseException, None, bool]=False) -> T:
    """Wish for some value, as specified by the passed Wish, and get that value

    Pass `from_exn=exn` to explicitly set the cause/context for the Wish to the exception
    `exn`; this is identical in behavior to doing `raise wish from exn` with exceptions.
    Likewise, you can pass `from_exn=None` to suppress the exception cause/context.

    We use the WishGranter currently bound to my_wish_granter in our ContextVar context to
    perform the wish. This is directly analogous to using the closest bound exception
    handler to handle an exception, and works the same way.

    """
    if not isinstance(wish, Wish):
        raise Exception("wishes should be of type Wish, not", wish)
    raising_exception = sys.exc_info()[1]
    if not isinstance(from_exn, bool):
        wish.__cause__ = from_exn
    elif raising_exception:
        wish.__context__ = raising_exception

    wish.__traceback__ = _frames_to_traceback([record.frame for record in inspect.stack()[1:]])

    wish_granter = my_wish_granter.get()
    ret = await wish_granter.wish(wish)
    return ret

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
            async_from_term = await self.thread.make_afd(from_term_pipe.read)
            async_to_term = await self.thread.make_afd(to_term_pipe.write)
            try:
                cat_stdin_thread = await self.thread.clone(unshare=CLONE.FILES)
                await cat_stdin_thread.task.inherit_fd(to_term_pipe.read).dup2(cat_stdin_thread.stdin)
                async with await cat_stdin_thread.exec(self.cat):
                    cat_stdout_thread = await self.thread.clone(unshare=CLONE.FILES)
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
        sockfd = await self.thread.make_afd(
            await self.thread.task.socket(AF.UNIX, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
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
                        await thread.close()
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
            connfd = await listenfd.thr.make_afd(await listenfd.accept())
            global_vars = {**initial_vars,
                           '__repls__': repl_vars,
                           '__repl_stdin__': connfd,
                           '__repl_stdout__': connfd}
            repl_vars[str(num)] = global_vars
            nursery.start_soon(do_repl, connfd, global_vars)
            num += 1
    return retval

def _initialize_module() -> None:
    import rsyscall.tasks.local as local
    my_wish_granter.set(trio.run(ConsoleGenie.make, local.thread))
_initialize_module()
