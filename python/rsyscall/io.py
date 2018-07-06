from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.epoll import EpollEvent, EPOLL_CLOEXEC
import rsyscall.epoll
import abc
import os
import typing as t
import trio
import signal
import sfork
from async_generator import asynccontextmanager
import logging
import fcntl
import errno
logger = logging.getLogger(__name__)

class SyscallInterface:
    async def pipe(self, flags=os.O_NONBLOCK) -> t.Tuple[int, int]: ...
    async def close(self, fd: int) -> None: ...
    # TODO add optional offset argument?
    # TODO figure out how to allow preadv2 flags?
    async def read(self, fd: int, count: int) -> bytes: ...
    async def write(self, fd: int, buf: bytes) -> int: ...
    async def dup2(self, oldfd: int, newfd: int) -> int: ...
    async def wait_readable(self, fd: int) -> None: ...
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int: ...
    async def exit(self, status: int) -> int: ...
    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> int: ...

    # epoll operations
    async def epoll_create(self, flags: int) -> int: ...
    async def epoll_ctl_add(self, epfd: int, fd: int, event: EpollEvent) -> None: ...
    async def epoll_ctl_mod(self, epfd: int, fd: int, event: EpollEvent) -> None: ...
    async def epoll_ctl_del(self, epfd: int, fd: int) -> None: ...
    async def epoll_wait(self, epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]: ...

    # we can do the same with ioctl
    # but not with prctl. what a mistake prctl is!
    async def fcntl(self, fd: int, cmd: int, arg: t.Union[bytes, int]=0) -> t.Union[bytes, int]:
        "This follows the same protocol as fcntl.fcntl."
        ...
    # for prctl we will have a separate method for each usage mode;
    # its interface is too diverse to do anything else and still abstract over the details of memory

class LocalSyscall(SyscallInterface):
    def __init__(self, wait_readable) -> None:
        self._wait_readable = wait_readable

    async def pipe(self, flags=os.O_CLOEXEC) -> t.Tuple[int, int]:
        logger.debug("pipe(%s)", flags)
        return os.pipe2(flags)

    async def close(self, fd: int) -> None:
        logger.debug("close(%d)", fd)
        return os.close(fd)

    # TODO allow setting offset?
    async def read(self, fd: int, count: int) -> bytes:
        logger.debug("read(%d, %d)", fd, count)
        return os.read(fd, count)

    async def write(self, fd: int, buf: bytes) -> int:
        logger.debug("write(%d, len(buf) == %d)", fd, len(buf))
        return os.write(fd, buf)

    async def dup2(self, oldfd: int, newfd: int) -> int:
        logger.debug("dup2(%d, %d)", oldfd, newfd)
        os.dup2(oldfd, newfd)
        return newfd

    # TODO support setting child_stack so we can create threads
    async def clone(self, flags: int, deathsig: t.Optional[signal.Signals]) -> int:
        logger.debug("clone(%d, %s)", flags, deathsig)
        if deathsig is not None:
            flags |= deathsig
        return sfork.clone(flags)

    async def exit(self, status: int) -> int:
        logger.debug("exit(%d)", status)
        return sfork.exit(status)

    async def execveat(self, dirfd: int, path: bytes,
                       argv: t.List[bytes], envp: t.List[bytes],
                       flags: int) -> int:
        logger.debug("execveat(%s)", path)
        return sfork.execveat(dirfd, path, argv, envp, flags)

    async def epoll_create(self, flags: int) -> int:
        logger.debug("epoll_create(%s)", flags)
        return rsyscall.epoll.epoll_create(flags)

    async def epoll_ctl_add(self, epfd: int, fd: int, event: EpollEvent) -> None:
        logger.debug("epoll_ctl_add(%d, %d, %s)", epfd, fd, event)
        rsyscall.epoll.epoll_ctl_add(epfd, fd, event)

    async def epoll_ctl_mod(self, epfd: int, fd: int, event: EpollEvent) -> None:
        logger.debug("epoll_ctl_mod(%d, %d, %s)", epfd, fd, event)
        rsyscall.epoll.epoll_ctl_mod(epfd, fd, event)

    async def epoll_ctl_del(self, epfd: int, fd: int) -> None:
        logger.debug("epoll_ctl_del(%d, %d)", epfd, fd)
        rsyscall.epoll.epoll_ctl_del(epfd, fd)

    async def epoll_wait(self, epfd: int, maxevents: int, timeout: int) -> t.List[EpollEvent]:
        logger.debug("epoll_wait(%d, maxevents=%d, timeout=%d)", epfd, maxevents, timeout)
        return rsyscall.epoll.epoll_wait(epfd, maxevents, timeout)

    # should we pull the file status flags when we create fhe file?
    # yyyyes theoretically.
    # should we store it in the FileDescriptor?
    # hah, no, we should have a FileObject...
    async def fcntl(self, fd: int, cmd: int, arg: t.Union[bytes, int]=0) -> t.Union[bytes, int]:
        "This follows the same protocol as fcntl.fcntl."
        logger.debug("fcntl(%d, %d, %s)", fd, cmd, arg)
        return fcntl.fcntl(fd, cmd, arg)

class FDNamespace:
    pass

class MemoryNamespace:
    pass

class Task:
    def __init__(self, syscall: SyscallInterface, files: FDNamespace, memory: MemoryNamespace) -> None:
        self.syscall = syscall
        self.memory = memory
        self.files = files

class ProcessContext:
    """A Linux process with associated resources.

    Resources chiefly include memory and file descriptors. Maybe other
    things at some point.

    Eventually, when we support pipelining file descriptor creation, we'll need some
    kind of transactional interface, or a list of "pending" fds.

    This also contains a fixed SyscallInterface that is used to access this process.
    """
    def __init__(self, syscall_interface: SyscallInterface) -> None:
        self.syscall = syscall_interface

T = t.TypeVar('T')
class FileObject:
    """This is the underlying file object referred to by a file descriptor.

    Often, multiple file descriptors in multiple processes can refer
    to the same file object. For example, the stdin/stdout/stderr file
    descriptors will typically all refer to the same file object
    across several processes started by the same shell.

    This is unfortunate, because there are some useful mutations (in
    particular, setting O_NONBLOCK) which we'd like to perform to
    FileObjects, but which might break other users.

    We store whether the FileObject is shared with others with
    "shared". If it is, we can't mutate it.

    """
    shared: bool
    def __init__(self, shared: bool=False, flags: int=None) -> None:
        self.shared = shared

    async def set_nonblock(self, fd: 'FileDescriptor[FileObject]') -> None:
        if self.shared:
            raise Exception("file object is shared and can't be mutated")
        await fd.syscall.fcntl(fd.number, fcntl.F_SETFL, os.O_NONBLOCK)

T_file = t.TypeVar('T_file', bound=FileObject)
T_file_co = t.TypeVar('T_file_co', bound=FileObject, covariant=True)

class ReadableFileObject(FileObject):
    async def read(self, fd: 'FileDescriptor[ReadableFileObject]', count: int=4096) -> bytes:
        return (await fd.syscall.read(fd.number, count))
ReadableFile = ReadableFileObject

class WritableFileObject(FileObject):
    async def write(self, fd: 'FileDescriptor[WritableFileObject]', buf: bytes) -> int:
        return (await fd.syscall.write(fd.number, buf))
WritableFile = WritableFileObject

class FileDescriptor(t.Generic[T_file_co]):
    "A file descriptor."
    file: T_file_co
    task: Task
    fd_namespace: FDNamespace
    number: int
    def __init__(self, file: T_file_co, task: Task, fd_namespace: FDNamespace, number: int) -> None:
        self.file = file
        self.task = task
        self.fd_namespace = fd_namespace
        self.number = number
        self.open = True

    @property
    def syscall(self) -> SyscallInterface:
        if self.task.files != self.fd_namespace:
            raise Exception("Can't call syscalls on FD when my Task has moved out of my FDNamespaces")
        return self.task.syscall

    async def aclose(self):
        if self.open:
            await self.syscall.close(self.number)
            self.open = False
        else:
            pass

    async def __aenter__(self) -> 'FileDescriptor[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    def release(self) -> 'FileDescriptor[T_file_co]':
        """Disassociate the file descriptor from this object

        """
        if self.open:
            self.open = False
            return self.__class__(self.file, self.task, self.fd_namespace, self.number)
        else:
            raise Exception("file descriptor already closed")

    async def dup2(self, target: 'FileDescriptor') -> 'FileDescriptor[T_file_co]':
        """Make a copy of this file descriptor at target.number

        """
        if self.fd_namespace != target.fd_namespace:
            raise Exception("two fds are not in the same FDNamespace")
        if self is target:
            return self
        owned_target: FileDescriptor = target.release()
        await self.syscall.dup2(self.number, owned_target.number)
        owned_target.open = False
        new_fd = type(self)(self.file, self.task, self.fd_namespace, owned_target.number)
        # dup2 unsets cloexec on the new copy, so:
        self.file.shared = True
        return new_fd

    async def enable_cloexec(self) -> None:
        self.file.shared = True
        raise NotImplementedError

    async def disable_cloexec(self) -> None:
        raise NotImplementedError

    # These are just helper methods which forward to the method on the underlying file object.
    async def set_nonblock(self: 'FileDescriptor[FileObject]') -> None:
        "Set the O_NONBLOCK flag on the underlying file object"
        await self.file.set_nonblock(self)

    async def read(self: 'FileDescriptor[ReadableFileObject]', count: int=4096) -> bytes:
        return (await self.file.read(self, count))

    async def write(self: 'FileDescriptor[WritableFileObject]', buf: bytes) -> int:
        return (await self.file.write(self, buf))

    async def add(self: 'FileDescriptor[EpollFileObject]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.add(self, fd, event)

    async def modify(self: 'FileDescriptor[EpollFileObject]', fd: 'FileDescriptor', event: EpollEvent) -> None:
        await self.file.modify(self, fd, event)

    async def delete(self: 'FileDescriptor[EpollFileObject]', fd: 'FileDescriptor') -> None:
        await self.file.delete(self, fd)

    async def wait(self: 'FileDescriptor[EpollFileObject]', maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await self.file.wait(self, maxevents, timeout))

    async def wait_readable(self) -> None:
        return (await self.syscall.wait_readable(self.number))

class EpollFileObject(FileObject):
    async def add(self, epfd: FileDescriptor['EpollFileObject'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_add(epfd.number, fd.number, event)

    async def modify(self, epfd: FileDescriptor['EpollFileObject'], fd: FileDescriptor, event: EpollEvent) -> None:
        await epfd.syscall.epoll_ctl_mod(epfd.number, fd.number, event)

    async def delete(self, epfd: FileDescriptor['EpollFileObject'], fd: FileDescriptor) -> None:
        await epfd.syscall.epoll_ctl_del(epfd.number, fd.number)

    async def wait(self, epfd: FileDescriptor['EpollFileObject'], maxevents: int=10, timeout: int=-1) -> t.List[EpollEvent]:
        return (await epfd.syscall.epoll_wait(epfd.number, maxevents, timeout))

async def allocate_epoll(task: Task) -> FileDescriptor[EpollFileObject]:
    epfd = await task.syscall.epoll_create(EPOLL_CLOEXEC)
    return FileDescriptor(EpollFileObject(), task, task.files, epfd)

class RawEpollWrapper:
    raw_epoller: 'RawEpoller'
    underlying: FileDescriptor
    def __init__(self, raw_epoller: 'RawEpoller', underlying: FileDescriptor) -> None:
        self.raw_epoller = raw_epoller
        self.underlying = underlying

    async def modify(self, event: EpollEvent) -> None:
        await self.raw_epoller.epfd.modify(self.underlying, event)

    async def aclose(self) -> None:
        await self.raw_epoller.epfd.delete(self.underlying)
        await self.underlying.aclose()

    async def __aenter__(self) -> 'RawEpollWrapper':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

class RawEpoller:
    def __init__(self, epfd: FileDescriptor[EpollFileObject]) -> None:
        self.epfd = epfd

    async def add(self, fd: FileDescriptor, event: EpollEvent) -> RawEpollWrapper:
        await self.epfd.add(fd, event)
        return RawEpollWrapper(self, fd)

    async def wait(self, maxevents: int=10, block: bool=True) -> t.List[EpollEvent]:
        if block:
            await self.epfd.wait_readable()
        return (await self.epfd.wait(maxevents=maxevents, timeout=0))

    async def aclose(self) -> None:
        await self.epfd.aclose()

    async def __aenter__(self) -> 'RawEpoller':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

async def allocate_raw_epoller(task: Task) -> RawEpoller:
    return RawEpoller(await allocate_epoll(task))

class EpollMultiplexer:
    def __init__(self, epoller) -> None:
        self.epoller = epoller
        self.dispatch: t.Dict[int, t.Tuple['Epollet', 'EpollWrapper']] = {}
        self.next_id = 1
        self.running_wait: t.Optional[trio.Event] = None

    def make(self) -> 'Epollet':
        return Epollet(self)

    async def add(self, epollet: 'Epollet', fd: FileDescriptor, event: EpollEvent) -> 'EpollWrapper':
        underlying_data = self.next_id
        self.next_id += 1
        user_data = event.data
        underlying = await self.epoller.add(fd, EpollEvent(data=underlying_data, events=event.events))
        wrapper = EpollWrapper(underlying_data, user_data, underlying, self)
        self.dispatch[underlying_data] = (epollet, wrapper)
        return wrapper

    async def do_wait(self) -> None:
        events = await self.epoller.wait()
        for event in events:
            epollet, wrapper = self.dispatch[event.data]
            epollet.queue.put_nowait(EpollEvent(data=wrapper.user_data, events=event.events))

    async def maybe_do_wait(self) -> None:
        if self.running_wait is not None:
            await self.running_wait
        else:
            running_wait = trio.Event()
            self.running_wait = running_wait
            await self.do_wait()
            self.running_wait = None
            running_wait.set()

class EpollWrapper:
    def __init__(self, underlying_data, user_data, underlying, multiplexer) -> None:
        self.underlying_data = underlying_data
        self.user_data = user_data
        self.underlying = underlying
        self.multiplexer = multiplexer

    async def modify(self, event: EpollEvent) -> None:
        await self.underlying.modify(EpollEvent(data=self.underlying_data, events=event.events))
        self.user_data = event.data

    async def aclose(self) -> None:
        await self.underlying.aclose()
        del self.multiplexer.dispatch[self.underlying_data]

class Epollet:
    def __init__(self, multiplexer: EpollMultiplexer) -> None:
        self.multiplexer = multiplexer
        self.queue = trio.hazmat.UnboundedQueue()

    # We need to take ownership of an FD, I guess.
    # urgh, because of the need to take ownership, multiplexing becomes rather silly
    # I guess at the time we take ownership, we'll also add the fd.
    # so add and delete become useless
    # modify is the only relevant one, and that is on the EpollWrapper
    async def add(self, fd: FileDescriptor, event: EpollEvent) -> EpollWrapper:
        return (await self.multiplexer.add(self, fd, event))

    # so the primary/sole functionality of this Epollet is to filter down EpollEvents
    async def wait(self, block: bool=True) -> t.List[EpollEvent]:
        # TODO okay so this is the hard part now.
        # we need to call wait or somefin
        # and then filter the result
        # can we filter it somehow?
        # can we maintain a set of the underlying data?
        # oh, we need to have the map from underlying to user data.
        # we have to transform the EpollEvents before rturning them, too, not just filter them.
        # what if we stick the dispatch thingy into this epollet?
        # nah we can't, since we also need to look up this epollet.
        # so ok
        # what if we just have a queue of epoll events in this thing?
        # and have the main epoll wrapper just put events in that queue?
        # then this wait just waits on that queue?
        # the annoying thing is having to run that guy in the background all the time.
        # although we can run it on demand I guess, pretty easily
        # hmm so when:
        # thread A runs do_wait
        # thread B shows up in the meantime
        # thread A finishes do_wait
        # thread A gets the events it wanted
        # then thread B needs to take over running do_wait
        while True:
            try:
                return self.queue.get_batch_nowait()
            except trio.WouldBlock:
                if block:
                    await self.multiplexer.maybe_do_wait()
                else:
                    return []

def create_current_task() -> Task:
    return Task(LocalSyscall(trio.hazmat.wait_readable),
                FDNamespace(), MemoryNamespace())

# TODO we should have a ProcessLaunchBootstrap which has these
# standard streams along with args/env and one task
class StandardStreams:
    stdin: FileDescriptor[ReadableFileObject]
    stdout: FileDescriptor[WritableFileObject]
    stderr: FileDescriptor[WritableFileObject]

    def __init__(self,
                 stdin: FileDescriptor[ReadableFileObject],
                 stdout: FileDescriptor[WritableFileObject],
                 stderr: FileDescriptor[WritableFileObject]) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

def wrap_stdin_out_err(task: Task) -> StandardStreams:
    stdin = FileDescriptor(ReadableFile(shared=True), task, task.files, 0)
    stdout = FileDescriptor(WritableFile(shared=True), task, task.files, 1)
    stderr = FileDescriptor(WritableFile(shared=True), task, task.files, 2)
    return StandardStreams(stdin, stdout, stderr)

class Pipe:
    def __init__(self, rfd: FileDescriptor[ReadableFile],
                 wfd: FileDescriptor[WritableFile]) -> None:
        self.rfd = rfd
        self.wfd = wfd

    async def aclose(self):
        await self.rfd.aclose()
        await self.wfd.aclose()

    async def __aenter__(self) -> 'Pipe':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

async def allocate_pipe(task: Task) -> Pipe:
    r, w = await task.syscall.pipe()
    return Pipe(FileDescriptor(ReadableFile(shared=False), task, task.files, r),
                FileDescriptor(WritableFile(shared=False), task, task.files, w))

class BigEpollWrapper(t.Generic[T_file_co]):
    """A class that encapsulates an O_NONBLOCK fd registered with epoll.

    Theoretically you might want to register with epoll and set
    O_NONBLOCK separately.  But that would mean you'd have to track
    them each with separate wrapper types, which would be too much
    overhead.

    """

    epoller: 'Epoller'
    underlying: FileDescriptor[T_file_co]
    def __init__(self, epoller: 'Epoller', fd: FileDescriptor[T_file_co]) -> None:
        self.epoller = epoller
        self.underlying = fd

    # ok time to implement this guy
    # alright well I guess I'll just go ahead and um..
    # I guess we want/need an event cache of some kind
    # ok so we run epoll
    # and we get a bunch of events back
    # and we store them all
    # and later people call wait_readable and it consumes the stored event
    # ugh.
    # how about just using a trio.Event?
    # we'll have some kind of data storage for each individual file object
    # we'll consume readability indicators...
    # a queue, I guess, of readability tokens
    # and a given task consumes one
    # I guess we just wait for the edge to go up?
    # meh heh heh...
    # we can't really do edge triggered if we want to allow the user to control reading
    # meh meh meh
    # what's the semantics we want?
    # we'd prefer that wait_readable just return immediately if the level is "readable",
    # and block otherwise.
    # we can't cache "the level is readable", or check it otherwise.
    # so we always need to call into epoll_wait.
    # when we call wait_readable,
    # we should check to see if we're already waiting for the level:
    # which would mean an Event already exists.
    # if one already exists, we wait on that.
    # if none exists, we create one and add our fd to the epfd.
    # then we check if someone is already waiting on the epfd.
    # if someone is, we wait for their results
    # if no-one is, we make an event for it and we start waiting on the epfd ourselves and set the Event when done.
    # once we have the results, we look through them to find our fd.
    # if we're in there, with the event type we want, we clear the field, set the Event, and return.
    async def wait_readable(self):
        # totally not multi-task-safe, also not safe for waiting for
        # both write and read at the same time.
        # hmm.
        # if we do the modification,
        # and we can immediately write,
        # then other things will start spinning
        # hmmm...
        # it feels like poll would actually be better.
        # if we could just say, hey here are the things we want to listen for on this epoll call.
        # can't we just model it as, we interrupt the call, and we resume it?
        # because, that's what it is...
        # yeah, so...
        # or alternatively, we call into thing and it returns up ehhh
        await self.modify(EpollEvent.make(42, in_=True))
        while True:
            results = await self.epoller.multiwait()
            if results[self.registered_event.data].in_:
                break
        await self.modify(EpollEvent.make(42, in_=False))
        # unset self.registered_event.in_
        if self.wait_readable_event:
            await self.wait_readable_event
        else:
            event = trio.Event()
            self.wait_readable_event = event
            while True:
                # TODO add fd to epoll
                # but, ugh, that conflicts with others possibly waiting at the same time
                # so we should actually just, um
                # check what we are currently registered for, and update it if necessary?
                results = await self.epoller.wait_for_epoll()
                if self.underlying in results:
                    if results[self.underlying].in_:
                        self.wait_readable_event = None
                        event.set()
                        return
            
            # n
            raise NotImplementedError

    async def wait_writable(self):
        raise NotImplementedError

    async def aclose(self):
        await self.epoller.delete(self.underlying)
        await self.underlying.aclose()

    async def __aenter__(self) -> 'BigEpollWrapper[T_file_co]':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.aclose()

    async def read(self: 'BigEpollWrapper[ReadableFileObject]', count: int=4096) -> bytes:
        while True:
            try:
                return (await self.underlying.read())
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    await self.wait_readable()
                else:
                    raise

class Epoller:
    epfd: FileDescriptor[EpollFileObject]
    def __init__(self, epfd: FileDescriptor[EpollFileObject]) -> None:
        self.epfd = epfd

    async def delete(self, epwrap: BigEpollWrapper) -> None:
        await self.epfd.file.delete(self.epfd, epwrap.underlying)

    async def wrap(self, fd: FileDescriptor[T_file]) -> BigEpollWrapper[T_file]:
        await fd.set_nonblock()
        return BigEpollWrapper(self, fd.release())

    async def __aenter__(self) -> 'Epoller':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.epfd.aclose()

async def allocate_epoller(task: Task) -> Epoller:
    epoll = await allocate_epoll(task)
    return Epoller(epoll)

class SubprocessContext:
    def __init__(self, task: Task, child_files: FDNamespace, parent_files: FDNamespace) -> None:
        self.task = task
        self.child_files = child_files
        self.parent_files = parent_files
        self.pid: t.Optional[int] = None

    def translate(self, fd: FileDescriptor[T_file]) -> FileDescriptor[T_file]:
        """Translate FDs from the parent's FilesNS to the child's FilesNS

        Any file descriptor created by my task in parent_files is now
        also present in child_files, so we're able to translate them
        to child_files.

        This only works for fds created by my task because fds from
        other tasks may have been created after the fork, through
        concurrent execution. To translate fds from other tasks,
        provide them as arguments at fork time.

        """
        if self.pid is not None:
            raise Exception("Already left the subprocess")
        if fd.fd_namespace != self.parent_files:
            raise Exception("Can't translate an fd not coming from my parent's FDNamespace")
        if fd.task != self.task:
            raise Exception("Can't translate an fd not coming from my Task; it could have been created after the fork.")
        return type(fd)(fd.file, fd.task, self.child_files, fd.number)

    @property
    def syscall(self) -> SyscallInterface:
        if self.pid is not None:
            raise Exception("Already left this process")
        return self.task.syscall

    async def exit(self, status: int) -> None:
        self.pid = await self.syscall.exit(status)
        self.task.files = self.parent_files

    async def exec(self, pathname: os.PathLike, argv: t.List[t.Union[str, bytes]],
             *, envp: t.Optional[t.Dict[str, str]]=None) -> None:
        if envp is None:
            envp = dict(**os.environ)
        self.pid = await self.syscall.execveat(sfork.AT_FDCWD,
                                               sfork.to_bytes(os.fspath(pathname)), [sfork.to_bytes(arg) for arg in argv],
                                               sfork.serialize_environ(**envp), flags=0)
        self.task.files = self.parent_files

@asynccontextmanager
async def subprocess(task: Task) -> t.Any:
    # this is really contextvar-ish. but I guess it's inside an
    # explicitly passed around object. but it's still the same kind of
    # behavior. by what name is this known?

    parent_files = task.files
    await task.syscall.clone(lib.CLONE_VFORK|lib.CLONE_VM, deathsig=None)
    child_files = FDNamespace()
    task.files = child_files
    context = SubprocessContext(task, child_files, parent_files)
    try:
        yield context
    finally:
        if context.pid is None:
            await context.exit(0)
