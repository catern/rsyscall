"""The core thread class required to fork a new child thread and call exec on it

We keep this separate so that helpers can be defined in terms of this
interface, and then attached to an omnibus Thread class.  For example,
mktemp.

"""
from __future__ import annotations
from rsyscall.command import Command
from rsyscall.environ import Environment
from rsyscall.epoller import Epoller
from rsyscall.handle import FileDescriptor, Task, WrittenPointer
from rsyscall.loader import NativeLoader
from rsyscall.memory.ram import RAM
from rsyscall.monitor import AsyncChildProcess, ChildProcessMonitor
from rsyscall.network.connection import Connection
from rsyscall.tasks.fork import ForkThread
import logging
import typing as t
import os

from rsyscall.fcntl import AT
from rsyscall.path import Path
from rsyscall.sched import CLONE
from rsyscall.signal import Sigset, SIG, SignalBlock, HowSIG
from rsyscall.unistd import Arg, ArgList

logger = logging.getLogger(__name__)

class UnixThread(ForkThread):
    def __init__(self,
                 task: Task,
                 ram: RAM,
                 connection: Connection,
                 loader: NativeLoader,
                 epoller: Epoller,
                 child_monitor: ChildProcessMonitor,
                 environ: Environment,
                 stdin: FileDescriptor,
                 stdout: FileDescriptor,
                 stderr: FileDescriptor,
    ) -> None:
        super().__init__(task, ram, epoller, connection, loader, child_monitor)
        self.environ = environ
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

    def _init_from(self, thr: UnixThread) -> None: # type: ignore
        super()._init_from(thr)
        self.environ = thr.environ
        self.stdin = thr.stdin
        self.stdout = thr.stdout
        self.stderr = thr.stderr

    async def fork(self, flags: CLONE=CLONE.SIGHAND) -> ChildUnixThread:
        "Create a new child thread"
        child_process, task = await self._fork_task(flags)
        ram = RAM(task,
                  # We don't inherit the transport because it leads to a deadlock:
                  # If when a child task calls transport.read, it performs a syscall in the child task,
                  # then the parent task will need to call waitid to monitor the child task during the syscall,
                  # which will in turn need to also call transport.read.
                  # But the child is already using the transport and holding the lock,
                  # so the parent will block forever on taking the lock,
                  # and child's read syscall will never complete.
                  self.ram.transport,
                  self.ram.allocator.inherit(task),
        )
        if flags & CLONE.NEWPID:
            # if the new process is pid 1, then CLONE_PARENT isn't allowed so we can't use inherit_to_child.
            # if we are a reaper, than we don't want our child CLONE_PARENTing to us, so we can't use inherit_to_child.
            # in both cases we just fall back to making a new ChildProcessMonitor for the child.
            epoller = await Epoller.make_root(ram, task)
            # this signal is already blocked, we inherited the block, um... I guess...
            # TODO handle this more formally
            signal_block = SignalBlock(task, await ram.ptr(Sigset({SIG.CHLD})))
            monitor = await ChildProcessMonitor.make(ram, task, epoller, signal_block=signal_block)
        else:
            epoller = self.epoller.inherit(ram)
            monitor = self.monitor.inherit_to_child(ram, task)
        return ChildUnixThread(UnixThread(
            task, ram,
            self.connection.inherit(task, ram),
            self.loader,
            epoller, monitor,
            self.environ.inherit(task, ram),
            stdin=self.stdin.inherit(task),
            stdout=self.stdout.inherit(task),
            stderr=self.stderr.inherit(task),
        ), process=child_process)

class ChildUnixThread(UnixThread):
    def __init__(self, thr: UnixThread, process: AsyncChildProcess) -> None:
        super()._init_from(thr)
        self.process = process

    async def _execve(self, path: Path, argv: t.List[bytes], envp: t.List[bytes]) -> AsyncChildProcess:
        "Call execve, abstracting over memory; self.{exec,execve} are probably preferable"
        async def op(sem: RAM) -> t.Tuple[WrittenPointer[Path],
                                               WrittenPointer[ArgList],
                                               WrittenPointer[ArgList]]:
            argv_ptrs = ArgList([await sem.ptr(Arg(arg)) for arg in argv])
            envp_ptrs = ArgList([await sem.ptr(Arg(arg)) for arg in envp])
            return (await sem.ptr(path),
                    await sem.ptr(argv_ptrs),
                    await sem.ptr(envp_ptrs))
        filename, argv_ptr, envp_ptr = await self.ram.perform_batch(op)
        await self.task.execve(filename, argv_ptr, envp_ptr)
        return self.process

    async def execve(self, path: Path,
                     argv: t.Sequence[t.Union[str, bytes, os.PathLike]],
                     env_updates: t.Mapping[str, t.Union[str, bytes, os.PathLike]]={},
                     inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> AsyncChildProcess:
        """Replace the running executable in this thread with another.

        self.exec is probably preferable; it takes a nice Command object which
        is easier to work with.

        We take inherited_signal_blocks as an argument so that we can default it
        to "inheriting" an empty signal mask. Most programs expect the signal
        mask to be cleared on startup. Since we're using signalfd as our signal
        handling method, we need to block signals with the signal mask; and if
        those blocked signals were inherited across exec, other programs would
        break (SIGCHLD is the most obvious example).

        We could depend on the user clearing the signal mask before calling
        exec, similar to how we require the user to remove CLOEXEC from
        inherited fds; but that is a fairly novel requirement to most, so for
        simplicity we just default to clearing the signal mask before exec, and
        allow the user to explicitly pass down additional signal blocks.

        """
        sigmask: t.Set[SIG] = set()
        for block in inherited_signal_blocks:
            sigmask = sigmask.union(block.mask)
        await self.task.sigprocmask((HowSIG.SETMASK, await self.ram.ptr(Sigset(sigmask))))
        envp: t.Dict[bytes, bytes] = {**self.environ.data}
        for key in env_updates:
            envp[os.fsencode(key)] = os.fsencode(env_updates[key])
        raw_envp: t.List[bytes] = []
        for key_bytes, value in envp.items():
            raw_envp.append(b''.join([key_bytes, b'=', value]))
        logger.debug("execveat(%s, %s, %s)", path, argv, env_updates)
        return await self._execve(path, [os.fsencode(arg) for arg in argv], raw_envp)

    async def exec(self, command: Command,
                   inherited_signal_blocks: t.List[SignalBlock]=[],
    ) -> AsyncChildProcess:
        """Replace the running executable in this thread with what's specified in `command`

        See self.execve's docstring for an explanation of inherited_signal_blocks.

        """
        return (await self.execve(command.executable_path, command.arguments, command.env_updates,
                                  inherited_signal_blocks=inherited_signal_blocks))
