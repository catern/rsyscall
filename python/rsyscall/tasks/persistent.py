import typing as t
import rsyscall.io as rsc
import rsyscall.base as base
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import RsyscallConnection, StandardTask, RsyscallInterface, Path, Task, SocketMemoryTransport, EpollWaiter, SyscallResponse, log_syscall, AsyncFileDescriptor, raise_if_error, ThreadMaker, FunctionPointer, CThread, SignalBlock, ChildProcessMonitor, ReadableWritableFile, robust_unix_bind, robust_unix_connect
import trio
import struct
from dataclasses import dataclass
import logging
import rsyscall.batch as batch

from rsyscall.struct import Bytes

from rsyscall.sched import CLONE
from rsyscall.sys.socket import SOCK, SendmsgFlags
from rsyscall.signal import Signals
from rsyscall.sys.prctl import PrctlOp

class PersistentConnection(base.SyscallInterface):
    """An reconnectable rsyscall connection; the task won't be our child on resume.

    For correctness, we should ensure that we'll get HUP/EOF if the task has
    exited and therefore will never respond. This is most easily achieved by
    making sure that the fds keeping the other end of the RsyscallConnection
    open, are only held by one task, and so will be closed when the task
    exits. Note, though, that that requires that the task be in an unshared file
    descriptor space.

    """
    def __init__(self, rsyscall_connection: RsyscallConnection,
                 process: near.Process,
                 path: Path) -> None:
        self.rsyscall_connection = rsyscall_connection
        self.logger = logging.getLogger(f"rsyscall.RsyscallConnection.{process.id}")
        self.identifier_process = process
        self.path = path
        # initialized by store_remote_side_handles
        self.infd: handle.FileDescriptor
        self.outfd: handle.FileDescriptor
        self.listening_fd: handle.FileDescriptor
        self.epoll_fd: handle.FileDescriptor
        self.activity_fd: near.FileDescriptor
        self.task: handle.Task
        # concurrency tracking stuff
        self.request_lock = trio.Lock()
        self.pending_responses: t.List[SyscallResponse] = []
        self.running: trio.Event = None

    def store_remote_side_handles(self,
                                  infd: handle.FileDescriptor,
                                  outfd: handle.FileDescriptor,
                                  listening_fd: handle.FileDescriptor,
                                  epoll_fd: handle.FileDescriptor,
                                  task: handle.Task,
    ) -> None:
        "We must call this with the remote side's used fds so we don't close them with GC"
        self.infd = infd
        self.outfd = outfd
        self.listening_fd = listening_fd
        self.epoll_fd = epoll_fd
        self.activity_fd = self.epoll_fd.near
        # hmmm I just need this so that I can make GC handles
        self.task = task

    async def reconnect(self, stdtask: StandardTask) -> None:
        await self.rsyscall_connection.close()
        [(access_sock, remote_sock)] = await stdtask.make_async_connections(1)
        connected_sock = await stdtask.task.socket_unix(SOCK.STREAM)
        self.path = self.path.with_task(stdtask.task)
        await robust_unix_connect(self.path, connected_sock)
        def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.SendMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights([remote_sock, remote_sock])]))
            return sem.to_pointer(handle.SendMsghdr(None, iovec, cmsgs))
        _, [] = await connected_sock.handle.sendmsg(await stdtask.task.perform_batch(sendmsg_op), SendmsgFlags.NONE)
        await remote_sock.invalidate()
        fd_bytes = await connected_sock.read()
        infd, outfd = struct.Struct("II").unpack(fd_bytes)
        self.rsyscall_connection = RsyscallConnection(access_sock, access_sock)
        self.infd = self.task.make_fd_handle(near.FileDescriptor(infd))
        self.outfd = self.task.make_fd_handle(near.FileDescriptor(outfd))

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def _process_response_for(self, response: SyscallResponse) -> None:
        try:
            ret = await self.rsyscall_connection.read_response()
            raise_if_error(ret)
        except Exception as e:
            response.set_exception(e)
        else:
            response.set_result(ret)

    async def _process_one_response_direct(self) -> None:
        if len(self.pending_responses) == 0:
            raise Exception("somehow we are trying to process a syscall response, when there are no pending syscalls.")
        next = self.pending_responses[0]
        await self._process_response_for(next)
        self.pending_responses = self.pending_responses[1:]

    async def _process_one_response(self) -> None:
        if self.running is not None:
            await self.running.wait()
        else:
            running = trio.Event()
            self.running = running
            try:
                await self._process_one_response_direct()
            finally:
                self.running = None
                running.set()

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        async with self.request_lock:
            log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
            await self.rsyscall_connection.write_request(
                number,
                arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
                arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        response = SyscallResponse(self._process_one_response)
        self.pending_responses.append(response)
        return response

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            # we must not be interrupted while reading the response - we need to return
            # the response so that our parent can deal with the state change we created.
            with trio.open_cancel_scope(shield=True):
                result = await response.receive()
        except Exception as exn:
            self.logger.debug("%s -> %s", number, exn)
            raise
        else:
            self.logger.debug("%s -> %s", number, result)
            return result


@dataclass
class PersistentServer:
    """The tracking object for a task which can be made to live on after the main process exits.

    The model we currently use for this is:
    1. Create this can-be-persistent task
    2. Do a bunch of things in that task, allocating whatever resources
    3. Call make_persistent to make the task actually persistent
    4. Crash or disconnect, and call reconnect to reconnect.

    It would be better for the model to be:
    1. Do a bunch of things in whatever task you like, allocating whatever resources
    2. Create an immediately persistent task which inherits those resources
    3. Crash or disconnect, and call reconnect to reconnect.

    However, the major obstacle is child processes. Child processes can't be inherited to a new
    child task, much less passed around between unrelated tasks like file descriptors can.

    CLONE_THREAD allows creating a new child task which can wait on the child processes of the
    parent; however, CLONE_THREAD also does a bunch of other stuff which is undesirable. Among other
    things, CLONE_THREAD tasks:
    - don't send SIGCHLD when exiting so they can't be waited on without dedicating a thread to block in wait
    - don't leave a zombie when they die
    - block several unshare and setns operations
    - complicate signals and many other system calls

    While CLONE_THREAD could allow the better model for persistent tasks, it comes with a host of
    other disadvantages and complexities, so we're just biting the bullet and accepting the worse
    model. Hopefully some new functionality might come along which allows inheriting or moving child
    processes without these disadvantages.

    """
    path: Path
    task: Task
    epoll_waiter: EpollWaiter
    syscall: RsyscallInterface
    listening_sock: handle.FileDescriptor
    transport: t.Optional[SocketMemoryTransport] = None

    async def _connect_and_send(self, stdtask: StandardTask, fds: t.List[handle.FileDescriptor]) -> t.List[near.FileDescriptor]:
        connected_sock = await stdtask.task.socket_unix(SOCK.STREAM)
        self.path = self.path.with_task(stdtask.task)
        await robust_unix_connect(self.path, connected_sock)
        await connected_sock.write(struct.pack('I', len(fds)))
        def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[handle.SendMsghdr]:
            iovec = sem.to_pointer(handle.IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(handle.CmsgList([handle.CmsgSCMRights(fds)]))
            return sem.to_pointer(handle.SendMsghdr(None, iovec, cmsgs))
        _, [] = await connected_sock.handle.sendmsg(await stdtask.task.perform_batch(sendmsg_op), SendmsgFlags.NONE)
        fd_bytes = await connected_sock.read()
        remote_fds = [near.FileDescriptor(i) for i, in struct.iter_unpack('I', fd_bytes)]
        await connected_sock.aclose()
        return remote_fds

    async def make_persistent(self) -> None:
        await self.task.base.setsid()
        await self.task.base.prctl(PrctlOp.SET_PDEATHSIG, 0)

    async def reconnect(self, stdtask: StandardTask) -> None:
        if self.syscall.pending_responses:
            raise Exception("can't reconnect while there are pending syscalls!")
        # TODO should also have the same check for transport, once we reify transport requests
        await self.syscall.rsyscall_connection.close()
        if self.transport is not None:
            await self.transport.local.aclose()
        # TODO hmm how do we handle closing the remote side, hmm...
        # we can invalidate it here, but not close it.
        # we could do the same for infd/outfd actually, I guess?
        # I suppose the reason we aren't is... to make sure that the cleanup happens even if we crash.
        # but we can always just clean up with another task...
        # hmmmmmmmmmMMMMMMMMMMMMMMMM i don't remember
        # yeah, I think we can handle it in python!
        # hmm, we could also handle manipulating the epoll from python. right?
        # ...yes the dependencies all are fine. we don't need to use an epoller to add something to an epfd.
        # so what we would need to do is, hold an epfd here in PersistentServer,
        # and maintain it as we connect and reconnect.
        # so, having some other thread handle the cleanup for an exited thread, does make sense.
        [(access_syscall_sock, syscall_sock), (access_data_sock, data_sock)] = await stdtask.make_async_connections(2)
        [infd, outfd, remote_data_sock] = await self._connect_and_send(
            stdtask, [syscall_sock, syscall_sock, data_sock])
        await syscall_sock.invalidate()
        await data_sock.invalidate()
        # update the syscall and transport with new connections
        # TODO it would be nice to be able to invalidate these immediately, and only then flush the closes afterwards.
        cleanup_remote_fds = [self.syscall.infd, self.syscall.outfd]
        if self.transport is not None:
            cleanup_remote_fds.append(self.transport.remote)
        self.syscall.rsyscall_connection = RsyscallConnection(access_syscall_sock, access_syscall_sock)
        self.syscall.infd = self.task.base.make_fd_handle(infd)
        self.syscall.outfd = self.task.base.make_fd_handle(outfd)
        # TODO technically this could still be in the same address space - that's the case in our tests.
        # we should figure out a way to give it a direct_transport=LocalMemoryTransport so it can copy efficiently
        transport = SocketMemoryTransport(access_data_sock, self.task.base.make_fd_handle(remote_data_sock),
                                          None)
        self.task.transport = transport
        self.transport = transport
        # close remote fds we are no longer using - can only do this here because we've
        # re-established the syscall connection
        for fd in cleanup_remote_fds:
            await fd.invalidate()

async def spawn_rsyscall_persistent_server(
        access_sock: AsyncFileDescriptor,
        remote_sock: handle.FileDescriptor,
        listening_sock: handle.FileDescriptor,
        parent_task: Task, thread_maker: ThreadMaker, function: handle.Pointer[handle.NativeFunction],
    ) -> t.Tuple[Task, CThread, RsyscallInterface, handle.FileDescriptor]:
    cthread = await thread_maker.make_cthread(
        (CLONE.VM|CLONE.FS|CLONE.FILES|CLONE.IO|
         CLONE.SIGHAND|CLONE.SYSVSEM|Signals.SIGCHLD),
        function, remote_sock.near, remote_sock.near, listening_sock.near)
    syscall = RsyscallInterface(RsyscallConnection(access_sock, access_sock),
                                cthread.child_task.process.near, remote_sock.near)
    new_base_task = base.Task(syscall, cthread.child_task.process.near, None,
                              parent_task.fd_table, parent_task.address_space, parent_task.base.fs,
                              parent_task.base.pidns,
                              parent_task.base.netns)
    remote_sock_handle = new_base_task.make_fd_handle(remote_sock)
    remote_listening_handle = new_base_task.make_fd_handle(listening_sock)
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    new_task = Task(new_base_task,
                    parent_task.transport.inherit(new_base_task),
                    parent_task.allocator.inherit(new_base_task),
                    parent_task.sigmask.inherit(),
    )
    return new_task, cthread, syscall, remote_listening_handle

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def fork_persistent(
        self: StandardTask, path: Path,
) -> t.Tuple[StandardTask, CThread, PersistentServer]:
    listening_sock = await self.task.socket_unix(SOCK.STREAM)
    await robust_unix_bind(path, listening_sock)
    await listening_sock.listen(1)
    [(access_sock, remote_sock)] = await self.make_async_connections(1)
    thread_maker = ThreadMaker(self.task, self.child_monitor, self.process)
    task, thread, syscall, listening_sock_handle = await spawn_rsyscall_persistent_server(
        access_sock, remote_sock, listening_sock.handle,
        self.task, thread_maker, self.process.persistent_server_func)
    await remote_sock.invalidate()
    await listening_sock.handle.invalidate()

    ## create the new persistent task
    epoller = await task.make_epoll_center()
    signal_block = SignalBlock(task, {Signals.SIGCHLD})
    # TODO use an inherited signalfd instead
    child_monitor = await ChildProcessMonitor.make(task, epoller, signal_block=signal_block)
    stdtask = StandardTask(
        self.access_task, self.access_epoller, self.access_connection,
        self.connecting_task,
        (self.connecting_connection[0], task.base.make_fd_handle(self.connecting_connection[1])),
        task, 
        self.process, self.filesystem,
        epoller,
        child_monitor,
        {**self.environment},
        stdin=self.stdin.for_task(task.base),
        stdout=self.stdout.for_task(task.base),
        stderr=self.stderr.for_task(task.base),
    )
    persistent_server = PersistentServer(path, task, epoller.epoller, syscall,
                                         listening_sock_handle)
    return stdtask, thread, persistent_server
