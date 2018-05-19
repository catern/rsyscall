from cffi import FFI
import pkgconfig

ffibuilder = FFI()
# include the rsyscall header
rsyscall = {key: list(value) for key, value in pkgconfig.parse('rsyscall').items()}
ffibuilder.set_source(
    "rsyscall._raw", """
#include <rsyscall.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/socket.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/mman.h>
#include <string.h>
#include <sched.h>
#include <setjmp.h>

static __thread jmp_buf exec_exit_jmp_buf;

int my_vfork() {
    int ret = vfork();
    printf("pid %d, vfork returned %d, buf %p\\n", getpid(), ret, &exec_exit_jmp_buf);
    if (ret > 0) {
	longjmp(exec_exit_jmp_buf, ret);
    } else {
        return ret;
    }
}

int my_exit(int status) {
    int ret = setjmp(exec_exit_jmp_buf);
    printf("pid %d, setjmp returned %d, buf %p\\n", getpid(), ret, &exec_exit_jmp_buf);
    if (ret > 0) {
	return ret;
    } else {
	_exit(status);
    }
}

long my_clone(unsigned long flags, void *child_stack,
           int *ptid, int *ctid,
           unsigned long newtls) {
    return syscall(SYS_clone, flags, child_stack,
                   ptid, ctid, newtls);
}

int syscall_exit(int status) {
    return syscall(SYS_exit, status);
}

long my_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5) {
    return syscall(number, arg1, arg2, arg3, arg4, arg5);
}

""", **rsyscall)
ffibuilder.cdef("""
long my_clone(unsigned long flags, void *child_stack,
           int *ptid, int *ctid,
           unsigned long newtls);
void my_vfork();
int my_exit(int status);
int vfork();
int syscall_exit(int status);

#define SYS_splice ...
#define SYS_pipe2 ...
#define SYS_close ...
#define SYS_mmap ...
#define SYS_munmap ...
#define SYS_preadv2 ...
#define SYS_pwritev2 ...
#define SYS_write ...
#define SYS_read ...

#define SYS_clone ...
#define SYS_vfork ...
#define SYS_exit ...
#define SYS_execveat ...

#define CLONE_VFORK ...
#define CLONE_VM ...

#define PROT_EXEC ...
#define PROT_READ ...
#define PROT_WRITE ...
#define PROT_NONE ...

#define MAP_SHARED ...
#define MAP_ANONYMOUS ...

long my_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5);
void *memcpy(void *dest, const void *src, size_t n);

struct sockaddr_in { ...; };

struct syscall { ...; };
struct syscall_response { ...; };
""")
# TODO need to get the struct definition
# TODO need to get the syscall numbers
# urgh
# include(rsyscall['include_dirs'])
# python is so terrible ARGH
# why do I have to repeat the cdefs here, ARGH
# okay okay I will do it.
# it's annoying but I'll do it.
# oh can I do the reading with just memcpy...

# I'll cast the return value of syscall to
# er no wait
# i'll take a pointer as an int,
# cast it to a pointer,
# make a buffer,
# copy thing around,
# all done it's good woo hoo

# for read, I can actually just cast it to a pointer and return it, right? neat.
# and for write, I just call out to memcpy.
