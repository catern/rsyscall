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

#define EPOLL_CLOEXEC ...

struct statx_timespec {
    __s64 tv_sec;    /* Seconds since the Epoch (UNIX time) */
    __u32 tv_nsec;   /* Nanoseconds since tv_sec */
};

struct statx {
    __u32 stx_mask;        /* Mask of bits indicating
                              filled fields */
    __u32 stx_blksize;     /* Block size for filesystem I/O */
    __u64 stx_attributes;  /* Extra file attribute indicators */
    __u32 stx_nlink;       /* Number of hard links */
    __u32 stx_uid;         /* User ID of owner */
    __u32 stx_gid;         /* Group ID of owner */
    __u16 stx_mode;        /* File type and mode */
    __u64 stx_ino;         /* Inode number */
    __u64 stx_size;        /* Total size in bytes */
    __u64 stx_blocks;      /* Number of 512B blocks allocated */
    __u64 stx_attributes_mask;
                           /* Mask to show what's supported
                              in stx_attributes */

    /* The following fields are file timestamps */
    struct statx_timestamp stx_atime;  /* Last access */
    struct statx_timestamp stx_btime;  /* Creation */
    struct statx_timestamp stx_ctime;  /* Last status change */
    struct statx_timestamp stx_mtime;  /* Last modification */

    /* If this file represents a device, then the next two
       fields contain the ID of the device */
    __u32 stx_rdev_major;  /* Major ID */
    __u32 stx_rdev_minor;  /* Minor ID */

    /* The next two fields contain the ID of the device
       containing the filesystem where the file resides */
    __u32 stx_dev_major;   /* Major ID */
    __u32 stx_dev_minor;   /* Minor ID */
};

int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);

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
