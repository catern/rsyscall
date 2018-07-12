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
#include <sys/epoll.h>
#include <string.h>
#include <sched.h>
#include <setjmp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

struct linux_dirent64 {
    ino64_t        d_ino;    /* 64-bit inode number */
    off64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    return syscall(SYS_getdents64, fd, dirp, count);
};

""", **rsyscall)
ffibuilder.cdef("""
typedef union epoll_data {
    uint64_t u64;
} epoll_data_t;
""")
ffibuilder.cdef("""
struct epoll_event {
  uint32_t     events;
  epoll_data_t data;
};
""", packed=True)
ffibuilder.cdef("""
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

#define EPOLL_CTL_ADD ...
#define EPOLL_CTL_MOD ...
#define EPOLL_CTL_DEL ...

#define AT_EMPTY_PATH ...
#define AT_SYMLINK_NOFOLLOW ...
#define AT_SYMLINK_FOLLOW ...
#define AT_REMOVEDIR ...

int unlinkat(int dirfd, const char *pathname, int flags);
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
long rsyscall_raw_syscall(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long sys);

#define EPOLL_CLOEXEC ...

typedef unsigned... ino64_t;
typedef signed... off64_t;

#define DT_BLK ... // This is a block device.
#define DT_CHR ... // This is a character device.
#define DT_DIR ... // This is a directory.
#define DT_FIFO ... // This is a named pipe (FIFO).
#define DT_LNK ... // This is a symbolic link.
#define DT_REG ... // This is a regular file.
#define DT_SOCK ... // This is a UNIX domain socket.
#define DT_UNKNOWN ... // The file type is unknown.

struct linux_dirent64 {
    ino64_t        d_ino;    /* 64-bit inode number */
    off64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
// needed to determine true length of the null-terminated filenames, which are null-padded
size_t strlen(const char *s);

int faccessat(int dirfd, const char *pathname, int mode, int flags);

#define SYS_splice ...
#define SYS_mmap ...
#define SYS_munmap ...
#define SYS_preadv2 ...
#define SYS_pwritev2 ...

#define SYS_openat ...
#define SYS_read ...
#define SYS_write ...
#define SYS_close ...
#define SYS_dup2 ...
#define SYS_pipe2 ...

#define SYS_chdir ...
#define SYS_fchdir ...

#define SYS_lseek ...
#define SYS_faccessat ...
#define SYS_mkdirat ...
#define SYS_getdents64 ...
#define SYS_unlinkat ...
#define SYS_linkat ...
#define SYS_symlinkat ...
#define SYS_readlinkat ...

#define SYS_prctl ...
#define SYS_getpid ...

#define SYS_epoll_ctl ...
#define SYS_epoll_wait ...
#define SYS_epoll_create1 ...

#define SYS_clone ...
#define SYS_vfork ...
#define SYS_exit ...
#define SYS_execveat ...

#define CLONE_VFORK ...
#define CLONE_VM ...
#define CLONE_FS ...
#define CLONE_FILES ...
#define CLONE_SIGHAND ...

#define PROT_EXEC ...
#define PROT_READ ...
#define PROT_WRITE ...
#define PROT_NONE ...

#define MAP_SHARED ...
#define MAP_ANONYMOUS ...
#define MAP_PRIVATE ...
#define MAP_GROWSDOWN ...
#define MAP_STACK ...

void *memcpy(void *dest, const void *src, size_t n);
void (*const rsyscall_server)(const int infd, const int outfd);
void rsyscall_trampoline(void);
struct rsyscall_trampoline_stack {
    int64_t rdi;
    int64_t rsi;
    int64_t rdx;
    int64_t rcx;
    int64_t r8;
    int64_t r9;
    void* function;
};

struct sockaddr_in { ...; };

struct syscall { ...; };
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
