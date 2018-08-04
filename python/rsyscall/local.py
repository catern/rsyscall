import shutil
import trio
from rsyscall.base import ServerInterface
import typing as t
import errno

rsyscall_server_location = shutil.which("rsyscall_server")
if not rsyscall_server_location:
    raise FileNotFoundError(errno.ENOENT, "Executable not found in PATH", "rsyscall_server")

# we don't need to represent a pipe that is half in our space and half in a server,
# because that is a rare case.
# all file descriptors should be in servers.

class ServerConnection:
    # TODO should we know all the file descriptors in this space immediately?
    # that is only necessary for pipelining, and also for dup2.
    # obviously we should know all the fds in this space.
    # we are the only person in this space...
    # but no, we could still want to inherit fds...
    # libraries...
    # practically, we have to know all the fds in the space,
    # and control when they're created,
    # for pipelining to work.
    # but that doesn't mean we can't pass an fd through this space!
    # oh, wait, but, we do create the fds in the space...
    # if something really does want to pass an fd around, it'll be some kind of highfd, abstract fd
    # so it seems like it might be fine to have all the fds be known...
    # there's basically two abstract things that we can pass around.
    # there's the small set of fds that points to the server, from which we can extract the knowledge of what fds are present.
    # and there's that set of fds + that full knowledge of fds in the server.
    # and that latter will be passed to a Python wrapper that then provides the useful functions.

    # yeah okay we need everything
    def __init__(self, tofd: int, fromfd: int) -> None:
        self.tofd = tofd
        self.fromfd = fromfd

# This abstraction kind of allows us to model the local process the same way...
class ProcessContext:
    """A Linux process with associated resources.

    Resources chiefly include memory and file descriptors. Maybe other
    things at some point.

    Eventually, when we support pipelining file descriptor creation, we'll need some
    kind of transactional interface, or a list of "pending" fds.
    """
    fds: t.Dict[int, FileDescriptor]

class FileDescriptor:
    """A file descriptor in some process context.

    """
    process: ProcessContext
    number: int

class ReadableFileDescriptor(FileDescriptor):
    pass

class WritableFileDescriptor(FileDescriptor):
    pass

class Stream:
    """A pair of file descriptors, one readable, one writable, within a single process.

    """
    __slots__ = ['process', '_readable', '_writable']
    process: ProcessContext
    _readable: int
    _writable: int
    @property
    def readable(self) -> ReadableFileDescriptor:
        fd = self.process.fds[self._readable]
        if isinstance(fd, ReadableFileDescriptor):
            return fd
        else:
            raise Exception
    @property
    def writable(self) -> WritableFileDescriptor:
        fd = self.process.fds[self._writable]
        if isinstance(fd, WritableFileDescriptor):
            return fd
        else:
            raise Exception

class InternalStream:
    """A pair of connected streams which talk to each other.

    Possibly across two processes, possibly within a single process. We control
    both ends, which is why it's "Internal".

    "local" and "remote" are not really local and remote. These names for the two
    sides just help conventional usage elsewhere.

    """
    local: Stream
    remote: Stream

class ProcessConnection:
    """A connection to some process speaking the rsyscall protocol.

    "local" is not truly local, it's just the ProcessContext we are using as a bridge
    to access self.process.

    Likewise, "remote" is not truly remote, it could be the local process if we want
    to perform syscalls asynchronously, or it could even be the same as local.

    """
    local: ProcessContext
    remote: ProcessContext
    # Invariant: self.syscall.local.process == self.local
    # Invariant: self.syscall.remote.process == self.remote
    syscall: InternalStream
    # Invariant: self.data.local.process == self.local
    # Invariant: self.data.remote.process == self.remote
    data: InternalStream

# so I need a ProcessConnection to do something inside a ProcessContext, to use a FileDescriptor...
# should I just have the ProcessConnections be attached to the ProcessContext?
# nah, for now I guess I'll have to explicitly pass it around?
# or rather, processconnection will be the method on which I call things. of course.

# okay.
# it's time to build a whole entire
# async io library
class Pointer:
    pass

class SyscallClient:
    def __init__(self, connection: ProcessConnection) -> None:
        self.connection = connection

    async def rsyscall(self, number=0, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
        request = build_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        # maybe need to do some kind of direct thing?
        # actually, I think we can just directly write?
        # oh, but we need to do the select.
        # so we need to create a big ole IO library.
        # yes, essentially we need to recreate the entire python standard IO library.
        # and I guess it would be nice to be able to use syscall() locally through CFFI :)
        await self.tofd().send(request)
        response = await self.fromfd().recv(4096)
        return syscall_response(response)

    async def splice(self, fd_in: int, fd_out: int, length: int,
                     off_in: Pointer=None, off_out: Pointer=None):
        return (await self.rsyscall(SYS.splice, fd_in, 0, fd_out, 0, length, 0))

class LocalServer(ServerInterface):
    def __init__(self, extra_fds: t.Dict={}) -> None:
        "Make a local server as a direct child"
        self.sock, remote_sock = trio.socket.socketpair()
        self.remote_sock = FileDescriptor(self, remote_sock.fileno())
        self.data_sock, remote_data_sock = trio.sock.socketpair()
        self.remote_data_sock = FileDescriptor(self, remote_sock.fileno())
        # TODO we need a trio-supporting supervise_api.Process which is separate from rsyscall,
        # with which to run the server.
        # TODO maybe the server should be run externally and the connection passed in to an owning class...
        self.process = supervise_api.Process(
            ['strace', '-o', 'log', rsyscall_server_location, str(self.remote_sock.number), str(self.remote_sock.number)],
            fds={self.remote_sock.number:remote_sock,
                 self.remote_data_sock.number:remote_data_sock, **extra_fds})
        remote_sock.close()
        remote_data_sock.close()

    async def pipe(self, fd_in: int, fd_out: int, length: int,
                     off_in: Pointer=None, off_out: Pointer=None):
        # what is the actual pipe syscall interface, that I need to know.
        # okay, I need remote memory to pass the fd array. argh.
        # is that right?
        # then I also need to implement remote write/remote read.
        # (pipelining the remote write/read with the syscall is a criticial optimization)
        # (fortunately pipe doesn't require I zero the memory first or anything. but pipelining the read afterwards would be good.)
        # so. remote alloc?
        # this is really some nice fault isolation.
        return (await self.rsyscall(SYS.splice, fd_in, 0, fd_out, 0, length, 0))

    def tofd(self):
        return self.sock

    def fromfd(self):
        return self.sock

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.sock.close()
        # TODO this is effectively check, and we want to do this continuously ofc
        ret = self.process.wait()
        if ret != 0:
            raise Exception("bad exit", ret)
        self.process.close()
