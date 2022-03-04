"""Process-independent interface to Linux system calls

rsyscall provides an interface to an ever-growing subset of Linux system calls. This interface is:

- *process-independent*: all system calls are called as methods on process objects,
  which can refer to the “local” process or to other processes under our control.
- *type-safe*: many Linux API constraints, which are usually left to user code to enforce,
  are made explicit in the type system.
- *low-level*: any action which is possible with the underlying Linux APIs, is possible with rsyscall;
  nothing is forbidden or discouraged.

## `Process`

The main entry point in rsyscall is the `Process`.
One `Process` exists for each process in which we can make system calls.

The initial `Process` is `rsyscall.tasks.local.local_process`, which operates in the Python interpreter process.
New processes are usually created by `Process.clone`, which returns a `ChildProcess`.

A `Process` has a number of other conventional, helpful resources,
which are almost always present.
For example, `Process.stdin`, `Process.stdout`, and `Process.stderr`.

## System calls on `Task`, `FileDescriptor`, etc.

`Process.task` points to the lower-level `Task` object.

All system calls exist either as methods on `Task`,
or as methods on objects (such as `FileDescriptor`) returned from `Task`,
which hold a reference to `Task`.

Read `rsyscall.doc.syscall_api` for an overview of the layout of the system call API.

`Task` makes syscalls and acesses memory using an internal instance of `rsyscall.near.sysif.SyscallInterface`.
The main implementations are `rsyscall.tasks.local.LocalSyscall` and `rsyscall.tasks.connection.SyscallConnection`.

The distinction between `Process` and `Task` is that `Task` provides only the bare minimum functionality guaranteed by Linux;
for example, it is not guaranteed that stdin/stdout/stderr actually exist, and `Task` does not assume they do.

## Memory allocation and access

Because a process may be in a separate address space,
memory allocation, and access by reading and writing, are explicit.
This is primarily done through the methods `Process.ptr` and `Process.malloc`,
which return `Pointer`s.
`Pointer`s are garbage collected, so memory freeing is automatic.

`Process` performs memory allocation and access using internal instances of
`rsyscall.memory.allocator.AllocatorInterface` and `rsyscall.memory.transport.MemoryTransport`.
The main allocator is `rsyscall.memory.allocator.BumpAllocator`,
and the main memory transports are `rsyscall.tasks.local.LocalSyscall`
and `rsyscall.tasks.connection.SyscallConnection`.

## Non-blocking operations

We can make system calls in multiple processes in parallel.
But in any specific process,
only one system call can happen at a time.

If a system call blocks, the process running it can't run other system calls.
This is undesirable, so `Process` comes with an epoll event loop,
`rsyscall.epoller.Epoller`,
so that we can wait for an epoll event and perform non-blocking system calls.

Use `Process.make_afd` to register a `FileDescriptor` with epoll
and get a corresponding `AsyncFileDescriptor`.

`AsyncFileDescriptor` supports `AsyncFileDescriptor.read`, `AsyncFileDescriptor.write`,
`AsyncFileDescriptor.accept`, `AsyncFileDescriptor.connect`, and other such system calls.
The interfaces are identical to `FileDescriptor`;
the async implementations simply wait for the appropriate epoll event before calling the underlying system call.

Many system calls can't meaningfully be done without blocking the process,
so use `AsyncFileDescriptor.handle` to access the underlying `FileDescriptor` to make those system calls.

For convenience,
`AsyncFileDescriptor` also has `AsyncFileDescriptor.read_some_bytes` and `AsyncFileDescriptor.write_all_bytes`,
which abstract over memory for simple use cases where efficient buffer management is not necessary.

Likewise, the `AsyncChildPid` object wraps `rsyscall.handle.ChildPid`
to perform non-blocking `AsyncChildPid.waitpid` operations on child process.
One will usually never deal with `ChildPid`,
because `ChildProcess.exec` returns an `AsyncChildPid`,
and that is the primary way to obtain child processes.

## Child processes

As mentioned above,
new processes are typically created by `Process.clone` which returns a `ChildProcess`.

As a convenience, the `Command` object bundles up an executable path, arguments, and environment variable updates.
The `ChildProcess.exec` takes a `Command` and execs into it.

The `rsyscall.environ.Environment.which` method looks up an executable name in `PATH` and returns a `Command` if found;
you can use this with `Process.environ`.

We'll often want to inherit file descriptors into child processes;
we can use `Task.inherit_fd` to get a handle for an inherited file descriptor,
and then `FileDescriptor.disable_cloexec` to allow it to be further inherited over `ChildProcess.exec`.

`rsyscall.tasks` describes several other ways to get new `Process`s,
including privilege-escalated `Process`s, `Process`s on remote hosts, and persistent `Process`s.

"""
from rsyscall.thread import Process, ChildProcess
from rsyscall.command import Command
from rsyscall.path import Path
from rsyscall.handle import (
    FileDescriptor, Task,
    WrittenPointer, Pointer,
    ReadablePointer, LinearPointer,
)
from rsyscall.epoller import AsyncFileDescriptor
from rsyscall.monitor import AsyncChildPid
from rsyscall.struct import Int32, Int64
from rsyscall.tasks.local import local_process
from rsyscall.sys.mman import MemoryMapping

__all__ = [
    'Process', 'ChildProcess',
    'Command',
    'Task',
    'FileDescriptor',
    'AsyncFileDescriptor',
    'AsyncChildPid',
    'local_process',
    'Pointer', 'WrittenPointer', 'ReadablePointer', 'LinearPointer',
]
