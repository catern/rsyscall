"""Documentation for the design of the system call API in rsyscall

## manpages are useful
rsyscall provides a type-safe, low-level, broad interface to a variety of Linux functionality.
This includes basic system calls,
like the socket API or read and write.
It also includes less common interfaces, such as inotify, rtnetlink, timerfd, eventfd, and others.

The Linux kernel manpages are the primary documentation for development against Linux.
This is true for rsyscall and Python just as it is true for C.

The manpages are therefore the primary documentation for programming with rsyscall.
All system calls in rsyscall are exposed in such a way
that a mechanical reading of the manpage for the system call
will provide sufficient information to use the system call in rsyscall.

We will discuss this translation through several examples,
and at the end we will have a small set of simple rules,
which one may apply to program with any supported system call in rsyscall.

## System calls and constants
The manpage for any Linux system call begins with a `SYNOPSIS` section,
which shows the prototype for the glibc wrapper for the system call,
and shows the headers which should be included to use that system call.

For example, [socket(2)](https://www.man7.org/linux/man-pages/man2/socket.2.html) begins:

```c
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

int socket(int domain, int type, int protocol);
```

The declaration of `socket` and associated constants is provided by the `sys/socket.h` header.

Sometimes, as with `socket(2)`,
additional headers (such as `sys/types.h`) will be present in the `SYNOPSIS` for backwards compatibility;
the last header listed is always the header containing the declaration.

As described in [socket(2)](https://www.man7.org/linux/man-pages/man2/socket.2.html),
the `domain` argument to `socket` takes one of a set of constants starting with `AF_`,
such as `AF_INET`.
These constants are defined by `sys/socket.h`.
Likewise, `type` takes a constant starting with `SOCK_`, also defined by `sys/socket.h`.
The third argument, `protocol`, is typically zero.

As described in the `RETURN VALUE` section,
`socket` returns an integer, which is a file descriptor;
on error, it returns a negative number (an invalid file descriptor) and sets `errno`.

An example call in C would then be:
```c
#include <sys/socket.h>

int sock = socket(AF_INET, SOCK_STREAM, 0);
```

In rsyscall, this syscall is defined as follows:
```python
from rsyscall.sys.socket import AF, SOCK
from rsyscall import FileDescriptor

class Task:
    async def socket(self, domain: AF, type: SOCK, protocol: int=0) -> FileDescriptor:
        ...
```

The types of the arguments to `rsyscall.Task.socket`, as described in the manpage,
are represented statically in the Python type system.
The `protocol` argument defaults to zero, for convenience.

`rsyscall.sys.socket.AF` and `rsyscall.sys.socket.SOCK` are `enum.IntEnum`s;
constant values such as `AF_INET` are accessed as `rsyscall.sys.socket.AF.INET`.

These constants are imported from the "header module" `rsyscall.sys.socket`,
with the name of the module patterned after the filename of the corresponding Linux C header `sys/socket.h`.
The header module for a system call, which contains all related values,
is always the last header in the `SYNOPSIS` section of that system call's manpage.

The return type of `rsyscall.Task.socket` is also represented statically in the Python type system.
`rsyscall.Task.socket` returns a `rsyscall.FileDescriptor`;
there is no corresponding type in C,
so it's imported from the top-level `rsyscall` module.

rsyscall never returns "invalid" values;
instead, on error, `rsyscall.Task.socket` throws `OSError`,
as is typical for Python.
There is no `errno` in rsyscall, only `OSError`s thrown from syscalls.

An example call in Python with rsyscall would then be:
```python
sock = await task.socket(AF.INET, SOCK.STREAM, 0)
```

To summarize, we've followed the following rules for this translation:
- If the last header included in the `SYNOPSIS` section of the manpage for a system call is `foo/bar.h`,
  values related to that system call are present in the header module `rsyscall.foo.bar`.
- Constants are represented as `enum.IntEnums` and can be imported from the syscall's header module.
- Types (such as `rsyscall.FileDescriptor`) which have no equivalent in C are imported from `rsyscall`,
  following Python class naming rules.
- System calls throw errors instead of setting errno.

## Structs and memory
Our next example is the `bind` system call.
The [bind(2)](https://www.man7.org/linux/man-pages/man2/bind.2.html) `SYNOPSIS` section contains:

```c
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

As described in [bind(2)](https://www.man7.org/linux/man-pages/man2/bind.2.html):
- `sockfd` is a socket file descriptor produced by the `socket` system call,
- `addr` is an initialized pointer to an address struct such as `struct sockaddr`,
- `addrlen` is the length of `addr`.

As described in the `RETURN VALUE` section,
`bind` returns zero on success;
on error, it returns a negative number and sets `errno`.

`bind(2)` mentions that to know the exact format of `addr`,
we need to refer to look at another manpage,
depending on the `AF` argument passed to the earlier `socket` call.
We'll use the socket file descriptor we made earlier with `AF.INET`,
so we'll look at the `ip(7)` manpage.

The `ip(7)` `SYNOPSIS` section contains:
```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
```

The manpage describes the definition of the `struct sockaddr_in` struct;
to see that definition, we can include `netinet/ip.h`.

The manpage mentions that the fields of `struct sockaddr_in` are in network byte order;
therefore, in C, we need to call `htons` to convert any value we store in the `.sin_port` field.

So an example call in C would be:
```c
#include <sys/socket.h>
#include <netinet/ip.h>

struct sockaddr_in addr = {
  .sin_family = AF_INET,
  .sin_port = htons(1234),
  .sin_addr = 0,
};
bind(sock, (struct sockaddr*) &addr, sizeof(addr));
```

In rsyscall, this syscall is defined as follows:
```python
from rsyscall.sys.socket import Sockaddr
from rsyscall.netinet.ip import SockaddrIn
from rsyscall import WrittenPointer

class FileDescriptor:
    async def bind(self, addr: WrittenPointer[Sockaddr]) -> None:
        ...
```

Since `rsyscall.FileDescriptor.bind` takes a file descriptor as its first argument,
it's defined as a method on `rsyscall.FileDescriptor`.

`rsyscall.sys.socket.Sockaddr` and `rsyscall.netinet.ip.SockaddrIn` are Python classes,
following Python class naming rules.
They implement `rsyscall.struct.Serializer.to_bytes` and `rsyscall.struct.Serializer.from_bytes`,
so they can be written to and read from memory as the corresponding C structs
`struct sockaddr` and `struct sockaddr_in`.
`rsyscall.netinet.ip.SockaddrIn` inherits from `rsyscall.sys.socket.Sockaddr`,
so it can be used anywhere `rsyscall.sys.socket.Sockaddr` can.

`rsyscall.WrittenPointer[rsyscall.sys.socket.Sockaddr]`
is an initialized pointer to a `rsyscall.sys.socket.Sockaddr` (or a derived type of `rsyscall.sys.socket.Sockaddr`).
Initialized pointers can be created by calling `rsyscall.Thread.ptr`,
passing a value of the appropriate type.

All `rsyscall.Pointer`s in rsyscall know their length,
so we never pass a separate length argument such as `addrlen`.

All `rsyscall.Pointer`s are garbage collected, so there's no need for manual freeing.

Since `rsyscall.FileDescriptor.bind` returns a fixed value of 0 on success,
it returns `None` in rsyscall, and like all other syscalls,
raises `OSError` to indicate an error.

An example call in Python with rsyscall would then be:
```python
addr = await thread.ptr(SockaddrIn(port=1234, addr=0))
await sock.bind(addr)
```

When creating the `rsyscall.netinet.ip.SockaddrIn`, we don't have to, nor should we, call `htons` on the port.
All rsyscall structs handle converting to and from network byte order
as part of `rsyscall.struct.Serializer.to_bytes` and `rsyscall.struct.Serializer.from_bytes`, where necessary.

The prefixes on the struct fields (the `sin_` on `sin_family`, `sin_port`, `sin_addr`) are removed;
those are [only necessary](https://stackoverflow.com/questions/10325870/why-are-the-fields-in-struct-stat-named-st-something/10325945) in C.
Positional arguments to the constructor, instead of keyword arguments, are also valid;
the argument positions are the same as the order of the fields in the struct.

The value for `family` must always be `AF_INET` for `rsyscall.netinet.ip.SockaddrIn`,
so it's set by default as a convenience for the user.

To summarize, we've added the following additional rules for this translation:
- System calls which operate on objects such as file descriptors
  are defined as methods on those objects.
- Structs passed to system calls are represented as Python classes following Python class naming rules,
  and can be imported from the appropriate header module.
- Complexities of reading and writing structures from memory, such as for network byte order, are abstracted away.
- Struct field prefixes are removed.
- Syscalls which take initialized pointers to memory take rsyscall `rsyscall.WrittenPointer`s of the appropriate type.
- `rsyscall.WrittenPointer`s can be created by passing a value of the appropriate type,
  such as Python class representations of structs, to `rsyscall.Thread.ptr`.
- Pointer length arguments are omitted in rsyscall.
* Malloc and syscalls which write to memory
Our next example is the `pipe` system call.
The [pipe(2)](https://www.man7.org/linux/man-pages/man2/pipe.2.html) `SYNOPSIS` section contains:

```c
#include <unistd.h>

int pipe(int pipefd[2]);
```

As described in [pipe(2)](https://www.man7.org/linux/man-pages/man2/pipe.2.html):
- Two file descriptors will be written to `pipefd`;
  `pipefd[0]` will contain the read end of the pipe
  and `pipefd[1]` will contain the write end of the pipe.

As described in the `RETURN VALUE` section,
`bind` returns zero on success;
on error, it returns a negative number and sets `errno`.

So an example call in C would be:
```c
#include <unistd.h>

int pipefd[2];
pipe(pipefd);
```

In rsyscall, `rsyscall.Task.pipe` is defined as follows:
```python
from rsyscall.unistd import Pipe

class Task:
    async def pipe(self, pipefd: Pointer[Pipe]) -> ReadablePointer[Pipe]:
        pass
```

Rather than an ad-hoc array, we pass a pointer to a type specific to `rsyscall.Task.pipe`, `rsyscall.unistd.Pipe`,
which will contain the two file descriptors once the `rsyscall.Task.pipe` call is done.

`rsyscall.Task.pipe` will write data to the passed-in `pipefd`,
wiping out whatever was there before,
so `pipefd` doesn't need to be initialized with data before it's passed in.
Therefore, it's a plain `rsyscall.Pointer`, not an `rsyscall.WrittenPointer`,
and we can allocate it with `rsyscall.Thread.malloc`.

The `rsyscall.Task.pipe` system call writes to the `pipefd` buffer,
so the passed-in `rsyscall.Pointer[rsyscall.unistd.Pipe]` is consumed and not usable after the call.
`rsyscall.Task.pipe` returns a new `rsyscall.ReadablePointer[rsyscall.unistd.Pipe]` for the same buffer,
from which we can read the `rsyscall.Task.pipe`.

An example call in Python with rsyscall would then be:
```python
pipefd = await thr.malloc(Pipe)
pipefd = await thr.task.pipe(pipefd)
read, write = await pipefd.read()
# or...
pipe = await pipefd.read()
assert pipe.read == pipe[0]
assert pipe.write == pipe[1]
```

To summarize, we've added the following additional rules for this translation:

- The few system calls which take arrays have types defined specifically for them, named after the system call.
- System calls which write to memory take `rsyscall.Pointer`s of the appropriate type.
- We can allocate an uninitialized `rsyscall.Pointer`
  by passing a type and (when appropriate) a size to `rsyscall.Thread.malloc`.
- System calls which write to memory consume the `rsyscall.Pointer`s that are passed in,
  and return one or more new `rsyscall.ReadablePointer`s for the readable portion of the passed-in buffers.

## Bitflags and syscalls which return a size
Our next and final example is the `recv` system call.
The [recv(2)](https://www.man7.org/linux/man-pages/man2/recv.2.html) `SYNOPSIS` section contains:
```c
#include <sys/types.h>
#include <sys/socket.h>

ssize_t recv(int sockfd, void *buf, size_t len, int flags);
```

As described in [recv(2)](https://www.man7.org/linux/man-pages/man2/recv.2.html):
- `sockfd` is a socket file descriptor
- `buf` is a pointer to some memory
- `len` is the maximum number of bytes which will be received from `sockfd` and written to `buf`
- `flags` is a bitflag, created by or-ing together constants starting with `MSG_`

As described in the `RETURN VALUE` section,
`recv` returns the number of bytes received and written to `buf`, which may be less than `len`.
On error, it returns a negative number and sets `errno`.

An example call in C would be:
```c
#include <sys/socket.h>

char buf[4096];
ssize_t size = recv(fd, buf, sizeof(buf), MSG_DONTWAIT|MSG_PEEK);
```

The user would then examine the first `size` bytes of `buf`;
the last `sizeof(buf) - size` bytes are uninitialized and invalid to load.

In rsyscall, this syscall is defined as follows:
```python
from rsyscall.sys.socket import MSG
from rsyscall import Pointer, ReadablePointer

class FileDescriptor:
    async def recv(self, buf: Pointer[bytes], flags: MSG) -> (ReadablePointer[bytes], Pointer[bytes]):
        ...
```

Like `rsyscall.FileDescriptor.bind`, since `rsyscall.FileDescriptor.recv` takes a file descriptor as its first argument,
it's defined as a method on `rsyscall.FileDescriptor`.

We pass a `rsyscall.Pointer[bytes]` as our buffer.
We can allocate one of these with `rsyscall.Thread.malloc`.
We pass an appropriate type and size to allocate to `rsyscall.Thread.malloc`,
and it returns a `rsyscall.Pointer` of that type and with that size.

As mentioned previously, `rsyscall.Pointer`s know their length,
so we don't need to pass `count` to `rsyscall.FileDescriptor.recv`.
If we want to pass a smaller value for `count`,
we can make a smaller buffer.

The `flags` argument, as mentioned previously, is typed as a Python `enum` class;
in this case, since it is a bitflag, it is an `enum.IntFlag`, which is combinable with bitwise operators.

To preserve type-safety of `rsyscall.FileDescriptor.recv` operations,
`rsyscall.FileDescriptor.recv` does not return a size.
Instead, it consumes `buf` and splits it into two new buffers, which it returns in a tuple.
This applies to all system calls which return a size,
such as `rsyscall.FileDescriptor.send`, `rsyscall.FileDescriptor.read`, `rsyscall.FileDescriptor.write`, and others.

The first element of the tuple is readable;
it points to the data which was received from the socket,
and which can now be read from memory with `rsyscall.ReadablePointer.read`.

The second element of the tuple is not readable;
it is the leftover part of the original buffer,
which was not filled with data from the socket.

We can check how much data was read by checking the size of the first pointer with `rsyscall.Pointer.size`.

An example call in Python with rsyscall would then be:
```python
from rsyscall.sys.socket import MSG

buf = await thread.malloc(bytes, 4096)
received, leftover = await sock.recv(buf, MSG.DONTWAIT|MSG.PEEK)
data = await received.read()
```

After the `rsyscall.FileDescriptor.recv` call, `buf` can no longer be used.
We can merge `received` and `leftover` back together with `rsyscall.Pointer.merge`:
`received.merge(leftover)`, or `received + leftover` for short.
Then we can reuse the resulting buffer.

To summarize, we've added the following additional rules:
- System calls returning sizes which offset into passed-in buffers return tuples of pointers:
  The first pointer points to the range from the start of the buffer to the size;
  the second pointer points to the range from the size to the end of the buffer.
  These two pointers will be different types depending on what operations are valid on each part of the buffer.

## Additional notes
### Everything is garbage collected
`rsyscall.FileDescriptor`s, `rsyscall.sys.mman.MemoryMapping`s, `rsyscall.handle.ChildProcess`es, and other resources
are all allocated through various system calls which return Python objects.
System calls related to these resources are present as methods on these objects.

rsyscall handles closing these resources once the last reference goes out of scope.
For example, when the last reference to a file descriptor goes out of scope, the file descriptor is closed.
The same applies for memory mappings, child processes, and other objects.

It is also possible to manually close an `rsyscall.FileDescriptor`
(or unmap an `rsyscall.sys.mman.MemoryMapping`, or kill a `rsyscall.handle.ChildProcess`)
if you want it to be deterministically closed.

### syscalls valid on multiple objects
Some syscalls can operate on multiple kinds of objects;
for example, `setpriority` can both operate on the current process and other processes.
In such cases, all the objects which are valid targets for the syscall will have a method for the syscall;
there's both a `rsyscall.Task.setpriority` and a `rsyscall.handle.Process.setpriority`.

### Deviations from Linux headers
In rare cases, to improve type safety and usability,
we will intentionally deviate from how the Linux headers define things.

Unfortunately, for such APIs you must resort to the rsyscall documentation to understand their usage.
We therefore avoid this wherever possible, but it's sometimes necessary.

`struct msghdr` is one example;
it is used differently by `rsyscall.FileDescriptor.sendmsg` and `rsyscall.FileDescriptor.recvmsg`,
and in the case of `rsyscall.FileDescriptor.recvmsg` also serves as an out-parameter.
To preserve type-safety,
it is represented with three classes,
`rsyscall.sys.socket.SendMsghdr`, `rsyscall.sys.socket.RecvMsghdr`, and `rsyscall.sys.socket.RecvMsghdrOut`.

### Missing syscalls
We seek to provide user-accessible low-level interfaces to the entirety of the Linux kernel,
including all non-obsolete syscalls,
and including things that are typically considered low-level implementation details (for example, `rsyscall.linux.futex`).

If you want to use some feature of the Linux kernel that is missing an interface in rsyscall,
we're happy to add support for it, just file an issue.
"""
