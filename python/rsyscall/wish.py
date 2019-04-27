from __future__ import annotations
import typing as t
import trio
import abc
import logging
import types
import traceback
import os
import inspect
import sys
from rsyscall.io import StandardTask, AsyncFileDescriptor, which, Command, Path, robust_unix_bind, ReadableFile, WritableFile, SocketFile, ReadableWritableFile
from contextvars import ContextVar
from rsyscall.sys.socket import SOCK, AF
import rsyscall.repl

logger = logging.getLogger(__name__)

# TODO should we inherit from BaseException or Exception?
T = t.TypeVar('T')
class Wish(BaseException, t.Generic[T]):
    return_type: t.Type[T]

    def __init__(self, return_type: t.Type[T], *args) -> None:
        self.return_type = return_type
        super().__init__(*args)

class WishGranter:
    @abc.abstractmethod
    async def wish(self, wish: Wish[T]) -> T: ...

class ConsoleGenie(WishGranter):
    @classmethod
    async def make(self, stdtask: StandardTask):
        cat = await which(stdtask, "cat")
        return ConsoleGenie(stdtask, cat)

    def __init__(self, stdtask: StandardTask, cat: Command) -> None:
        self.stdtask = stdtask
        self.cat = cat
        self.lock = trio.Lock()

    async def wish(self, wish: Wish[T]) -> T:
        async with self.lock:
            message = "".join(traceback.format_exception(None, wish, wish.__traceback__))
            wisher_frame = [frame for (frame, lineno) in traceback.walk_tb(wish.__traceback__)][-1]
            catfd, myfd = await self.stdtask.task.socketpair(AF.UNIX, SOCK.STREAM, 0)

            term_stdin, repl_stdout = await self.stdtask.task.pipe()
            repl_stdin, term_stdout = await self.stdtask.task.pipe()
            async_stdin = await AsyncFileDescriptor.make(self.stdtask.epoller, repl_stdin)
            async_stdout = await AsyncFileDescriptor.make(self.stdtask.epoller, repl_stdout)
            try:
                cat_stdin_thread = await self.stdtask.fork()
                cat_stdin = cat_stdin_thread.stdtask.task.base.make_fd_handle(term_stdin.handle)
                await term_stdin.handle.invalidate()
                await cat_stdin_thread.stdtask.unshare_files(going_to_exec=True)
                await cat_stdin_thread.stdtask.stdin.replace_with(cat_stdin)
                async with await self.cat.exec(cat_stdin_thread):
                    cat_stdout_thread = await self.stdtask.fork()
                    cat_stdout = cat_stdout_thread.stdtask.task.base.make_fd_handle(term_stdout.handle)
                    await term_stdout.handle.invalidate()
                    await cat_stdout_thread.stdtask.unshare_files(going_to_exec=True)
                    await cat_stdout_thread.stdtask.stdout.replace_with(cat_stdout)
                    async with await self.cat.exec(cat_stdout_thread):
                        ret = await run_repl(async_stdin, async_stdout, {
                            '__repl_stdin__': async_stdin,
                            '__repl_stdout__': async_stdout,
                            'wish': wish,
                            'wisher_frame': wisher_frame,
                            'wisher_locals': wisher_frame.f_locals,
                            'wisher_globals': wisher_frame.f_globals,
                        }, wish.return_type, message)
                        return ret
            finally:
                await async_stdin.aclose()
                await async_stdout.aclose()

class ConsoleServerGenie(WishGranter):
    @classmethod
    async def make(self, stdtask: StandardTask, sockdir: Path):
        socat = await which(stdtask, "socat")
        return ConsoleServerGenie(stdtask, sockdir, socat)

    def __init__(self, stdtask: StandardTask, sockdir: Path, socat: Command) -> None:
        self.stdtask = stdtask
        self.sockdir = sockdir
        self.socat = socat
        self.name_counts: t.Dict[str, int] = {}

    def _uniquify_name(self, name: str) -> str:
        "We never reuse a name."
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
        sockfd = await self.stdtask.task.socket_unix(SOCK.STREAM)
        await robust_unix_bind(sock_path, sockfd)
        await sockfd.listen(10)
        async_sockfd = await AsyncFileDescriptor.make(self.stdtask.epoller, sockfd)
        async with trio.open_nursery() as nursery:
            @nursery.start_soon
            async def do_socat():
                while True:
                    thread = await self.stdtask.fork()
                    try:
                        child = await cmd.exec(thread)
                    except:
                        await thread.close()
                        raise
                    async with child:
                        await child.wait_for_exit()
            ret = await serve_repls(async_sockfd, {
                'wisher_frame': wisher_frame,
                'wisher_locals': wisher_frame.f_locals,
                'wisher_globals': wisher_frame.f_globals,
            }, wish.return_type, message)
            nursery.cancel_scope.cancel()
        await sock_path.unlink()
        return ret

my_wish_granter: ContextVar[WishGranter] = ContextVar('wish_granter')

def frames_to_traceback(frames: t.List[types.FrameType]) -> t.Optional[types.TracebackType]:
    tb = None
    for frame in frames:
        tb = types.TracebackType(tb, frame, frame.f_lasti, frame.f_lineno)
    return tb

# TODO should switch bool to typing_extensions.Literal[False]
# we allow passing None for from_exn to suppress the context
async def wish(wish: Wish[T], from_exn: t.Union[BaseException, None, bool]=False) -> T:
    raising_exception = sys.exc_info()[1]
    if not isinstance(from_exn, bool):
        wish.__cause__ = from_exn
    elif raising_exception:
        wish.__context__ = raising_exception

    wish.__traceback__ = frames_to_traceback([record.frame for record in inspect.stack()[1:]])

    wish_granter = my_wish_granter.get()
    ret = await wish_granter.wish(wish)
    return ret

async def run_repl(infd: AsyncFileDescriptor,
                   outfd: AsyncFileDescriptor,
                   global_vars: t.Dict[str, t.Any],
                   wanted_type: t.Type[T], message: str) -> T:
    async with trio.open_nursery() as repl_nursery:
        @repl_nursery.start_soon
        async def wait_for_rdhup() -> None:
            await infd.wait_for_rdhup()
            # when we get RDHUP on the connection, we want to cancel the REPL, even if
            # some task is in progress.
            raise Exception("REPL connection hangup")
        await outfd.write((message+"\n").encode())
        ret = await rsyscall.repl.run_repl(infd.read, outfd.write, global_vars, wanted_type)
        repl_nursery.cancel_scope.cancel()
    return ret

async def serve_repls(listenfd: AsyncFileDescriptor,
                      initial_vars: t.Dict[str, t.Any],
                      wanted_type: t.Type[T], message: str) -> T:
    """Serves REPLs on a socket until someone gives us the type we want

    Hmm. Tricky. Do we need multiple threads here? I guess that's the easiest way.

    Yeah... better that than anything else.

    hmm it would be nice to be able to cancel a single repl or something

    interrupt the running task from outside. hm.

    yeah let's support that so that we can kill repls, um.

    maybe not

    """
    repl_vars: t.Dict[str, t.Dict[str, t.Any]] = {}
    retval = None
    async with trio.open_nursery() as nursery:
        async def do_repl(connfd: AsyncFileDescriptor,
                          global_vars: t.Dict[str, t.Any]) -> None:
            try:
                ret = await run_repl(connfd, connfd, global_vars, wanted_type, message)
            except rsyscall.repl.FromREPL as e:
                raise e.exn from e
            except Exception:
                logger.exception("run_repl's internal logic raised an exception, disconnecting that REPL and continuing")
            else:
                nonlocal retval
                retval = ret
                nursery.cancel_scope.cancel()
            finally:
                await connfd.aclose()
        num = 0
        while True:
            connfd: AsyncFileDescriptor
            connfd, _ = await listenfd.accept_as_async()
            global_vars = {**initial_vars, '__repls__': repl_vars, '__repl_stdin__': connfd,  '__repl_stdout__': connfd}
            repl_vars[str(num)] = global_vars
            nursery.start_soon(do_repl, connfd, global_vars)
            num += 1
    return retval

async def _init_wish_granter(stdtask: StandardTask) -> None:
    my_wish_granter.set(await ConsoleGenie.make(stdtask))
def _initialize_module() -> None:
    import rsyscall.tasks.local as local
    trio.run(_init_wish_granter, local.stdtask)
_initialize_module()