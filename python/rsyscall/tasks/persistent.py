import typing as t
import rsyscall.io as rsc
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import RsyscallConnection, StandardTask, RsyscallInterface, Path, Task, SocketMemoryTransport, SyscallResponse, log_syscall, AsyncFileDescriptor, raise_if_error, ChildProcessMonitor

from rsyscall.io import ProcessResources, Trampoline
from rsyscall.handle import Stack, WrittenPointer, ThreadProcess, Pointer

import trio
import struct
from dataclasses import dataclass
import logging
import rsyscall.batch as batch

from rsyscall.struct import Bytes, Int32, StructList

from rsyscall.sched import CLONE
from rsyscall.sys.socket import AF, SOCK, Address, SendmsgFlags, SendMsghdr, CmsgSCMRights, CmsgList
from rsyscall.sys.uio import IovecList
from rsyscall.signal import Signals, Sigset, SignalBlock
from rsyscall.sys.prctl import PrctlOp

__all__ = [
    "fork_persistent",
]

class PersistentConnection(near.SyscallInterface):
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
        await connected_sock.connect(await self.path.as_sockaddr_un())
        def sendmsg_op(sem: batch.BatchSemantics) -> handle.WrittenPointer[SendMsghdr]:
            iovec = sem.to_pointer(IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(CmsgList([handle.CmsgSCMRights([remote_sock, remote_sock])]))
            return sem.to_pointer(SendMsghdr(None, iovec, cmsgs))
        _, [] = await connected_sock.handle.sendmsg(await stdtask.task.perform_batch(sendmsg_op), SendmsgFlags.NONE)
        await remote_sock.invalidate()
        fd_bytes = await connected_sock.read()
        infd, outfd = struct.Struct("II").unpack(fd_bytes)
        self.rsyscall_connection = RsyscallConnection(access_sock, access_sock)
        self.infd = self.task.make_fd_handle(near.FileDescriptor(infd))
        self.outfd = self.task.make_fd_handle(near.FileDescriptor(outfd))

    async def close_interface(self) -> None:
        await self.rsyscall_connection.close()

    async def submit_syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> SyscallResponse:
        log_syscall(self.logger, number, arg1, arg2, arg3, arg4, arg5, arg6)
        conn_response = await self.rsyscall_connection.write_request(
            number,
            arg1=int(arg1), arg2=int(arg2), arg3=int(arg3),
            arg4=int(arg4), arg5=int(arg5), arg6=int(arg6))
        response = SyscallResponse(self.rsyscall_connection.read_pending_responses, conn_response)
        return response

    async def syscall(self, number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
        response = await self.submit_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        try:
            # we must not be interrupted while reading the response - we need to return
            # the response so that our parent can deal with the state change we created.
            with trio.CancelScope(shield=True):
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
    syscall: RsyscallInterface
    listening_sock: handle.FileDescriptor
    # saved to keep the reference to the stack pointer etc alive
    thread_process: ThreadProcess
    transport: t.Optional[SocketMemoryTransport] = None

    async def _connect_and_send(self, stdtask: StandardTask, fds: t.List[handle.FileDescriptor]) -> t.List[near.FileDescriptor]:
        connected_sock = await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM, 0)
        self.path = self.path.with_task(stdtask.task)
        sockaddr_un = await self.path.as_sockaddr_un()
        def sendmsg_op(sem: batch.BatchSemantics) -> t.Tuple[
                WrittenPointer[Address], WrittenPointer[Int32], WrittenPointer[SendMsghdr], Pointer[StructList[Int32]]]:
            addr: WrittenPointer[Address] = sem.to_pointer(sockaddr_un)
            count = sem.to_pointer(Int32(len(fds)))
            iovec = sem.to_pointer(IovecList([sem.malloc_type(Bytes, 1)]))
            cmsgs = sem.to_pointer(CmsgList([handle.CmsgSCMRights(fds)]))
            hdr = sem.to_pointer(SendMsghdr(None, iovec, cmsgs))
            response_buf = sem.to_pointer(StructList(Int32, [Int32(0)]*len(fds)))
            return addr, count, hdr, response_buf
        addr, count, hdr, response = await stdtask.ram.perform_batch(sendmsg_op)
        await connected_sock.connect(addr)
        await sockaddr_un.close()
        _, _ = await connected_sock.write(count)
        _, [] = await connected_sock.sendmsg(hdr, SendmsgFlags.NONE)
        data = None
        while response.bytesize() > 0:
            valid, response = await connected_sock.read(response)
            data += valid
        remote_fds = [near.FileDescriptor(int(i)) for i in (await data.read()).elems] if data else []
        await connected_sock.close()
        return remote_fds

    async def make_persistent(self) -> None:
        await self.task.base.setsid()
        await self.task.base.prctl(PrctlOp.SET_PDEATHSIG, 0)

    async def reconnect(self, stdtask: StandardTask) -> None:
        # TODO should check that no transport requests are in flight
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
        # we should figure out a way to use a LocalMemoryTransport here so it can copy efficiently
        transport = SocketMemoryTransport(access_data_sock,
                                          self.task.base.make_fd_handle(remote_data_sock), self.task.allocator)
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
        parent_task: Task, process_resources: ProcessResources,
    ) -> t.Tuple[Task, RsyscallInterface, handle.FileDescriptor, ThreadProcess]:
    async def op(sem: batch.BatchSemantics) -> t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]]:
        stack_value = process_resources.make_trampoline_stack(Trampoline(
            process_resources.persistent_server_func, [remote_sock, remote_sock, listening_sock]))
        stack_buf = sem.malloc_type(handle.Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        return stack
    stack = await parent_task.perform_async_batch(op)
    thread_process = await parent_task.base.clone(
        (CLONE.VM|CLONE.FS|CLONE.FILES|CLONE.IO|
         CLONE.SIGHAND|CLONE.SYSVSEM|Signals.SIGCHLD),
        stack, None, None, None)
    syscall = RsyscallInterface(RsyscallConnection(access_sock, access_sock),
                                thread_process.near, remote_sock.near)
    new_base_task = handle.Task(syscall, thread_process.near, None,
                              parent_task.base.fd_table, parent_task.base.address_space, parent_task.base.fs,
                              parent_task.base.pidns,
                              parent_task.base.netns)
    new_base_task.sigmask = parent_task.base.sigmask
    remote_sock_handle = new_base_task.make_fd_handle(remote_sock)
    remote_listening_handle = new_base_task.make_fd_handle(listening_sock)
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    new_task = Task(new_base_task,
                    parent_task.transport.inherit(new_base_task),
                    parent_task.allocator.inherit(new_base_task),
    )
    return new_task, syscall, remote_listening_handle, thread_process

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def fork_persistent(
        self: StandardTask, path: Path,
) -> t.Tuple[StandardTask, PersistentServer]:
    listening_sock = await self.task.socket_unix(SOCK.STREAM)
    await listening_sock.bind(await path.as_sockaddr_un())
    await listening_sock.listen(1)
    [(access_sock, remote_sock)] = await self.make_async_connections(1)
    task, syscall, listening_sock_handle, thread_process = await spawn_rsyscall_persistent_server(
        access_sock, remote_sock, listening_sock.handle,
        self.task, self.process)
    await remote_sock.invalidate()
    await listening_sock.handle.invalidate()

    ## create the new persistent task
    epoller = await task.make_epoll_center()
    signal_block = SignalBlock(task.base, await task.to_pointer(Sigset({Signals.SIGCHLD})))
    # TODO use an inherited signalfd instead
    child_monitor = await ChildProcessMonitor.make(task, task.base, epoller, signal_block=signal_block)
    stdtask = StandardTask(
        self.connection.for_task(task.base, task),
        task, 
        self.process,
        epoller,
        child_monitor,
        self.environ.inherit(task.base, task),
        stdin=self.stdin.for_task(task.base),
        stdout=self.stdout.for_task(task.base),
        stderr=self.stderr.for_task(task.base),
    )
    persistent_server = PersistentServer(path, task, syscall, listening_sock_handle, thread_process)
    return stdtask, persistent_server
