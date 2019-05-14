import typing as t
import rsyscall.io as rsc
import rsyscall.near as near
import rsyscall.far as far
import rsyscall.handle as handle
from rsyscall.io import RsyscallConnection, StandardTask, Path, SocketMemoryTransport, SyscallResponse, log_syscall, AsyncFileDescriptor, raise_if_error, ChildProcessMonitor
from rsyscall.tasks.common import NonChildSyscallInterface
from rsyscall.loader import NativeLoader, Trampoline
from rsyscall.handle import Stack, WrittenPointer, ThreadProcess, Pointer

import trio
import struct
from dataclasses import dataclass
import logging
import rsyscall.batch as batch

from rsyscall.memory.ram import RAM

from rsyscall.epoller import EpollCenter

from rsyscall.struct import Bytes, Int32, StructList

from rsyscall.sched import CLONE
from rsyscall.sys.socket import AF, SOCK, Address, SendmsgFlags, SendMsghdr, CmsgSCMRights, CmsgList
from rsyscall.sys.uio import IovecList
from rsyscall.signal import Signals, Sigset, SignalBlock
from rsyscall.sys.prctl import PrctlOp

__all__ = [
    "fork_persistent",
]

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
    task: handle.Task
    ram: RAM
    syscall: NonChildSyscallInterface
    listening_sock: handle.FileDescriptor
    # saved to keep the reference to the stack pointer etc alive
    thread_process: ThreadProcess
    transport: t.Optional[SocketMemoryTransport] = None

    async def _connect_and_send(self, stdtask: StandardTask, fds: t.List[handle.FileDescriptor]) -> t.List[near.FileDescriptor]:
        connected_sock = await stdtask.task.base.socket(AF.UNIX, SOCK.STREAM, 0)
        self.path = self.path.with_thread(stdtask.ramthr)
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
        await self.task.setsid()
        await self.task.prctl(PrctlOp.SET_PDEATHSIG, 0)

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
        [(access_syscall_sock, syscall_sock), (access_data_sock, data_sock)] = await stdtask.open_async_channels(2)
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
        self.syscall.infd = self.task.make_fd_handle(infd)
        self.syscall.outfd = self.task.make_fd_handle(outfd)
        # TODO technically this could still be in the same address space - that's the case in our tests.
        # we should figure out a way to use a LocalMemoryTransport here so it can copy efficiently
        transport = SocketMemoryTransport(access_data_sock,
                                          self.task.make_fd_handle(remote_data_sock), self.ram.allocator)
        self.ram.transport = transport
        self.transport = transport
        # close remote fds we are no longer using - can only do this here because we've
        # re-established the syscall connection
        for fd in cleanup_remote_fds:
            await fd.invalidate()

async def spawn_rsyscall_persistent_server(
        access_sock: AsyncFileDescriptor,
        remote_sock: handle.FileDescriptor,
        listening_sock: handle.FileDescriptor,
        parent_task: handle.Task,
        parent_ram: RAM,
        loader: NativeLoader,
    ) -> t.Tuple[handle.Task, RAM, NonChildSyscallInterface, handle.FileDescriptor, ThreadProcess]:
    async def op(sem: batch.BatchSemantics) -> t.Tuple[handle.Pointer[Stack], WrittenPointer[Stack]]:
        stack_value = loader.make_trampoline_stack(Trampoline(
            loader.persistent_server_func, [remote_sock, remote_sock, listening_sock]))
        stack_buf = sem.malloc_type(handle.Stack, 4096)
        stack = await stack_buf.write_to_end(stack_value, alignment=16)
        return stack
    stack = await parent_ram.perform_async_batch(op)
    thread_process = await parent_task.clone(
        (CLONE.VM|CLONE.FS|CLONE.FILES|CLONE.IO|
         CLONE.SIGHAND|CLONE.SYSVSEM|Signals.SIGCHLD),
        stack, None, None, None)
    syscall = NonChildSyscallInterface(RsyscallConnection(access_sock, access_sock),
                                       thread_process.near)
    new_base_task = handle.Task(syscall, thread_process.near, None,
                                parent_task.fd_table, parent_task.address_space, parent_task.fs,
                                parent_task.pidns,
                                parent_task.netns)
    new_base_task.sigmask = parent_task.sigmask
    remote_sock_handle = remote_sock.move(new_base_task)
    remote_listening_handle = listening_sock.move(new_base_task)
    syscall.store_remote_side_handles(remote_sock_handle, remote_sock_handle)
    new_ram = RAM(new_base_task,
                  parent_ram.transport.inherit(new_base_task),
                  parent_ram.allocator.inherit(new_base_task),
    )
    return new_base_task, new_ram, syscall, remote_listening_handle, thread_process

# this should be a method, I guess, on something which points to the persistent stuff resource.
async def fork_persistent(
        self: StandardTask, path: Path,
) -> t.Tuple[StandardTask, PersistentServer]:
    listening_sock = await self.task.socket(AF.UNIX, SOCK.STREAM)
    await listening_sock.bind(await self.ram.to_pointer(await path.as_sockaddr_un()))
    await listening_sock.listen(1)
    [(access_sock, remote_sock)] = await self.open_async_channels(1)
    task, ram, syscall, listening_sock_handle, thread_process = await spawn_rsyscall_persistent_server(
        access_sock, remote_sock, listening_sock,
        self.task, self.ram, self.loader)

    ## create the new persistent task
    epoller = await EpollCenter.make_root(ram, task)
    signal_block = SignalBlock(task, await ram.to_pointer(Sigset({Signals.SIGCHLD})))
    # TODO use an inherited signalfd instead
    child_monitor = await ChildProcessMonitor.make(ram, task, epoller, signal_block=signal_block)
    stdtask = StandardTask(
        task, ram,
        self.connection.for_task(task, ram),
        self.loader,
        epoller,
        child_monitor,
        self.environ.inherit(task, ram),
        stdin=self.stdin.for_task(task),
        stdout=self.stdout.for_task(task),
        stderr=self.stderr.for_task(task),
    )
    persistent_server = PersistentServer(path, task, ram, syscall, listening_sock_handle, thread_process)
    return stdtask, persistent_server
