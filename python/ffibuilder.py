from cffi import FFI
import pkgconfig
import pathlib
import shutil

# We store paths at build time
stored_paths = {
    "pkglibexecdir": pkgconfig.variables('rsyscall')['pkglibexecdir'],
    "rm_path": shutil.which("rm"),
    "sh_path": shutil.which("sh"),
    "ssh_path": shutil.which("ssh"),
}

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
#include <sys/mount.h>
#include <sys/un.h>
#include <netinet/ip.h> /* superset of previous */
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <poll.h>
#include <string.h>
#include <sched.h>
#include <setjmp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/signalfd.h>
#include <sys/ptrace.h>
#include <dirent.h>

struct linux_dirent64 {
    ino64_t        d_ino;    /* 64-bit inode number */
    off64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

// the double underscores are hard to use from Python,
// since they will be replaced with the class name
#define _WNOTHREAD __WNOTHREAD
#define _WCLONE __WCLONE
#define _WALL __WALL

struct robust_list {
  struct robust_list *next;
};

struct robust_list_head {
  struct robust_list list;
  long futex_offset;
  struct robust_list *list_op_pending;
};

// sigh, glibc doesn't export these
#define FUTEX_WAITERS 0x80000000
#define FUTEX_TID_MASK 0x3fffffff
""" + "\n".join(f'const char {name}[] = "{value}";' for name, value in stored_paths.items()), **rsyscall)
for name in stored_paths:
    ffibuilder.cdef(f"const char {name}[];")
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

#define AT_FDCWD ...
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

// needed to determine true length of the null-terminated filenames, which are null-padded
size_t strlen(const char *s);

int faccessat(int dirfd, const char *pathname, int mode, int flags);

// signal stuff
#define SYS_waitid ...
#define SYS_kill ...

#define WEXITED ...
#define WSTOPPED ...
#define WCONTINUED ...
#define WNOHANG ...
#define WNOWAIT ...
#define _WCLONE ...
#define _WALL ...
#define _WNOTHREAD ...
#define P_PID ...
#define P_PGID ...
#define P_ALL ...
#define CLD_EXITED ... // child called _exit(2)
#define CLD_KILLED ... // child killed by signal
#define CLD_DUMPED ... // child killed by signal, and dumped core
#define CLD_STOPPED ... // child stopped by signal
#define CLD_TRAPPED ... // traced child has trapped
#define CLD_CONTINUED ... // child continued by SIGCONT
typedef int... pid_t;
typedef unsigned... uid_t;
typedef struct siginfo {
    int      si_code;      /* Signal code */
    pid_t    si_pid;       /* Sending process ID */
    uid_t    si_uid;       /* Real user ID of sending process */
    int      si_status;    /* Exit value or signal */
    ...;
} siginfo_t;

#define SYS_signalfd4 ...

#define SFD_NONBLOCK ...
#define SFD_CLOEXEC ...

#define SYS_rt_sigprocmask ...

#define SIG_BLOCK ...
#define SIG_UNBLOCK ...
#define SIG_SETMASK ...


struct signalfd_siginfo {
    uint32_t ssi_signo;    /* Signal number */
    int32_t  ssi_errno;    /* Error number (unused) */
    int32_t  ssi_code;     /* Signal code */
    uint32_t ssi_pid;      /* PID of sender */
    uint32_t ssi_uid;      /* Real UID of sender */
    int32_t  ssi_fd;       /* File descriptor (SIGIO) */
    uint32_t ssi_tid;      /* Kernel timer ID (POSIX timers)
    uint32_t ssi_band;     /* Band event (SIGIO) */
    uint32_t ssi_overrun;  /* POSIX timer overrun count */
    uint32_t ssi_trapno;   /* Trap number that caused signal */
    int32_t  ssi_status;   /* Exit status or signal (SIGCHLD) */
    int32_t  ssi_int;      /* Integer sent by sigqueue(3) */
    uint64_t ssi_ptr;      /* Pointer sent by sigqueue(3) */
    uint64_t ssi_utime;    /* User CPU time consumed (SIGCHLD) */
    uint64_t ssi_stime;    /* System CPU time consumed
                              (SIGCHLD) */
    ...;
};

#define SYS_splice ...
#define SYS_preadv2 ...
#define SYS_pwritev2 ...

#define SYS_openat ...
#define SYS_read ...
#define SYS_write ...
#define SYS_recvfrom ...
#define SYS_close ...
#define SYS_dup3 ...
#define SYS_pipe2 ...
#define SYS_ftruncate ...

#define SYS_chdir ...
#define SYS_fchdir ...

#define SYS_lseek ...
#define SYS_faccessat ...
#define SYS_mkdirat ...
#define SYS_getdents64 ...
#define SYS_unlinkat ...
#define SYS_linkat ...
#define SYS_renameat2 ...
#define SYS_symlinkat ...
#define SYS_readlinkat ...


// prctl
#define SYS_prctl ...
#define PR_SET_PDEATHSIG ...

#define SYS_getpid ...
#define SYS_setsid ...

// epoll stuff
#define SYS_epoll_ctl ...
#define SYS_epoll_wait ...
#define SYS_epoll_create1 ...

// poll stuff
#define SYS_poll ...

struct pollfd {
    int   fd;         /* file descriptor */
    short events;     /* requested events */
    short revents;    /* returned events */
};

#define POLLIN ...
#define POLLHUP ...
#define POLLERR ...
#define POLLNVAL ...

// task stuff
#define SYS_clone ...
#define SYS_vfork ...
#define SYS_exit ...
#define SYS_exit_group ...
#define SYS_execveat ...
#define SYS_unshare ...
#define SYS_setns ...
#define SYS_set_tid_address ...

#define SYS_getuid ...
#define SYS_getgid ...

#define CLONE_VFORK ...
#define CLONE_CHILD_CLEARTID ...
#define CLONE_PARENT ...

#define CLONE_VM ...
#define CLONE_SIGHAND ...
#define CLONE_IO ...
#define CLONE_SYSVSEM ...

#define CLONE_FILES ...
#define CLONE_FS ...
#define CLONE_NEWCGROUP ...
#define CLONE_NEWIPC ...
#define CLONE_NEWNET ...
#define CLONE_NEWNS ...
#define CLONE_NEWPID ...
#define CLONE_NEWUSER ...
#define CLONE_NEWUTS ...
#define CLONE_SYSVSEM ...

// mount stuff
#define SYS_mount ...
#define MS_BIND ...
#define MS_REC ...
#define MS_RDONLY ...
#define MS_REMOUNT ...

// socket stuff
#define SYS_socket ...
#define SYS_socketpair ...
#define SYS_bind ...
#define SYS_listen ...
#define SYS_accept4 ...
#define SYS_connect ...
#define SYS_getsockname ...
#define SYS_getpeername ...

#define SOCK_NONBLOCK ...
#define SOCK_CLOEXEC ...

typedef unsigned... sa_family_t;

#define AF_UNIX ...
struct sockaddr_un {
    sa_family_t sun_family;               /* AF_UNIX */
    char        sun_path[108];            /* pathname */
};

#define AF_INET ...
typedef unsigned... in_port_t;
struct sockaddr_in {
    sa_family_t    sin_family; /* address family: AF_INET */
    in_port_t      sin_port;   /* port in network byte order */
    struct in_addr sin_addr;   /* internet address */
    ...;
};

/* Internet address. */
struct in_addr {
    uint32_t       s_addr;     /* address in network byte order */
};

// sockopt stuff
#define SYS_getsockopt ...
#define SYS_setsockopt ...

#define SOL_SOCKET ...
#define SO_ERROR ...

// fcntl stuff
#define SYS_fcntl ...

#define F_GETFD ...

// mmap stuff
#define SYS_mmap ...
#define SYS_munmap ...
#define SYS_memfd_create ...

#define MFD_CLOEXEC ...

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
// we need these as function pointers, we aren't calling them from Python
int (*const rsyscall_persistent_server)(int infd, int outfd, const int listensock);
int (*const rsyscall_server)(const int infd, const int outfd);
void (*const rsyscall_futex_helper)(void *futex_addr);
void (*const rsyscall_trampoline)(void);
void (*const rsyscall_do_cloexec)(int* excluded_fds, int fd_count);
void (*const rsyscall_stop_then_close)(int* excluded_fds, int fd_count);

struct rsyscall_trampoline_stack {
    int64_t rdi;
    int64_t rsi;
    int64_t rdx;
    int64_t rcx;
    int64_t r8;
    int64_t r9;
    void* function;
};

struct rsyscall_syscall {
    int64_t sys;
    int64_t args[6];
};
struct rsyscall_symbol_table {
    void* rsyscall_server;
    void* rsyscall_persistent_server;
    void* rsyscall_do_cloexec;
    void* rsyscall_stop_then_close;
    void* rsyscall_futex_helper;
    void* rsyscall_trampoline;
};
struct rsyscall_bootstrap {
    struct rsyscall_symbol_table symbols;
    pid_t pid;
    int listening_sock;
    int syscall_sock;
    int data_sock;
    int envp_count;
};
struct rsyscall_stdin_bootstrap {
    struct rsyscall_symbol_table symbols;
    pid_t pid;
    int syscall_fd;
    int data_fd;
    int futex_memfd;
    int envp_count;
};

#define SYS_sendmsg ...
#define SYS_recvmsg ...

struct iovec {
    void *iov_base;	/* Pointer to data.  */
    size_t iov_len;	/* Length of data.  */
};

typedef unsigned long int socklen_t;
struct msghdr {
    void *msg_name;		/* Address to send to/receive from.  */
    int msg_namelen;     	/* Length of address data.  */
  
    struct iovec *msg_iov;	/* Vector of data to send/receive into.  */
    unsigned long int msg_iovlen;		/* Number of elements in the vector.  */
  
    void *msg_control;		/* Ancillary data (eg BSD filedesc passing). */
    unsigned long int msg_controllen;	/* Ancillary data buffer length.  */
  
    int msg_flags;		/* Flags in received message.  */
};

struct cmsghdr {
    unsigned long int cmsg_len;		/* Length of data in cmsg_data plus length
				   of cmsghdr structure.  */
    int cmsg_level;		/* Originating protocol.  */
    int cmsg_type;		/* Protocol specific type.  */
    ...;
};

//// ugh, have to take this over to get notification of thread exec
#define SYS_set_robust_list ...

// see kernel source for documentation
struct robust_list {
  struct robust_list *next;
};

struct robust_list_head {
  struct robust_list list;
  long futex_offset;
  struct robust_list *list_op_pending;
};

#define FUTEX_WAITERS ...
#define FUTEX_TID_MASK ...

""")
