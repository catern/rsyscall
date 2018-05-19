from rsyscall._raw import ffi, lib # type: ignore
import rsyscall.io
import os
import signal
import typing as t

def syscall(number, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> int:
    print("before", number, arg1, arg2, arg3, arg4, arg5, arg6)
    val = lib.my_syscall(number, arg1, arg2, arg3, arg4, arg5)
    print("returning from syscall value", val)
    print("after", number, arg1, arg2, arg3, arg4, arg5, arg6)
    if (val == -1):
        err = ffi.errno
        raise OSError(err, os.strerror(err))
    return val

def clone(flags: int, deathsig: t.Optional[signal.Signals]) -> int:
    if deathsig is not None:
        flags |= deathsig
    return syscall(lib.SYS_clone, flags, 0, 0, 0, 0)

def my_exit(status: int) -> int:
    print("exit", status)
    return syscall(lib.SYS_exit, status)

signal.signal(signal.SIGCHLD, signal.SIG_IGN)

# theory: vfork restores EIP.
# therefore I need to make syscalls through the same function entry point.
# if I have two separate functions, they could be compiled differently.
# that seems legit, and likely, but does not explain the behavior I'm seeing with nested functions.

# So remember: make syscalls through the same entry point and you'll be okay!

# okay, so maybe the issue is not eip, but other registers.
# that are interpreted weirdly by the python VM or need to be saved or something?
# oh, or the stack pointer...
# the stack pointer is restored...
# ESP arrggh
# so maybe I need to save the registers and restore them?

# in theory I really like the notion of,
# you have a single thread of control, you push a new process context on the stack,
# you set things up,
# and then you make a new thread in that process context and return to the old one.
# blah, I'll emulate the vfork I want in userspace.
# and maybe include it with supervise_api?
# vfork should not restore the parent's registers.
# the child's registers are part of the memory space!

# oh nice, vfork on Linux doesn't suspend the whole process, just the calling thread, good good.

# so the setuid issue is an issue with setuid in one thread that shares memory with other threads.
# meh! setuid sucks, don't use it.

# vfork should not restore the parent's registers
# "cons should not evaluate its arguments"

# okay I can store the registers in a global static struct after each exec/exit,
# and load them after vfork returns in the parent.
# and this can be a standalone C library.
# it's fine that it's global because syscalls are already global.
# er, it's not thread-safe though.
# is it?
# if we vfork twice in the parent,
# and we exec in the opposite order in the children,
# the threads that resume can get mixed up.
# that's... fine, I guess...
# well, it might be a little/very confusing.
# using thread local storage might be nicer, if it's easy.
# and then we exec in another thread.
# (thread local storage?)
# oh! we can have static thread local storage anyway. so I'll just use that!
# and maybe I'll have it be a setjmp/longjmp?
print("pid 1", os.getpid())
lib.my_vfork()
# clone(lib.CLONE_VFORK|lib.CLONE_VM, signal.SIGCHLD)
print("pid 2", os.getpid())
print((lambda: lib.my_exit(0))())
# my_exit(0)
print("pid 3", os.getpid())
