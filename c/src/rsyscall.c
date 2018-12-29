#define _GNU_SOURCE
#include <stddef.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stdnoreturn.h>
#include "rsyscall.h"
#include <err.h>

#include <sys/prctl.h>
#include <sys/types.h>

#include <fcntl.h>
#include <dirent.h>

struct options {
        int infd;
        int outfd;
};

char hello[] = "hello world, I am the syscall server!\n";
char read_failed[] = "rsyscall: read(infd, &request, sizeof(request)) failed\n";
char read_eof[] = "rsyscall: read(infd, &request, sizeof(request)) returned EOF\n";
char write_failed[] = "rsyscall: write(outfd, &response, sizeof(response)) failed\n";

static long write(int fd, const void *buf, size_t count) {
    return rsyscall_raw_syscall(fd, (long) buf, (long) count, 0, 0, 0, SYS_write);
}
static long read(int fd, void *buf, size_t count) {
    return rsyscall_raw_syscall(fd, (long) buf, (long) count, 0, 0, 0, SYS_read);
}

static void exit(int status) {
    rsyscall_raw_syscall(status, 0, 0, 0, 0, 0, SYS_exit);
}

static void error(char* msg, size_t msgsize) {
    write(2, msg, msgsize);
    exit(1);
}

static int read_request(const int infd, struct rsyscall_syscall *request)
{
    char* buf = (char*) request;
    size_t remaining = sizeof(*request);
    while (remaining) {
        long const ret = read(infd, buf, remaining);
        if (ret < 0) {
	    write(2, read_failed, sizeof(read_failed) - 1);
	    return ret;
	}
        if (ret == 0) {
            write(2, read_eof, sizeof(read_eof) - 1);
	    return 0;
        }
        remaining -= ret;
        buf += ret;
    }
    return 1;
}

static int64_t perform_syscall(struct rsyscall_syscall request)
{
    return rsyscall_raw_syscall(request.args[0], request.args[1], request.args[2],
                       request.args[3], request.args[4], request.args[5],
                       request.sys);
}

static int write_response(const int outfd, const int64_t response)
{
    char* data = (char*) &response;
    size_t remaining = sizeof(response);
    while (remaining) {
        long const ret = write(outfd, data, remaining);
        if (ret < 0) {
	    write(2, write_failed, sizeof(write_failed) - 1);
	    return ret;
	}
        remaining -= ret;
        data += ret;
    }
    return 1;
}

long getdents64(int fd, char* buf, unsigned int count) {
    return rsyscall_raw_syscall(fd, (long)buf, count, 0, 0, 0, SYS_getdents64);
}

long getfd(int fd) {
    return rsyscall_raw_syscall(fd, F_GETFD, 0, 0, 0, 0, SYS_fcntl);
}

long myopen(char* path, int flags) {
    return rsyscall_raw_syscall((long)path, flags, 0, 0, 0, 0, SYS_open);
}

static long close(int fd) {
    return rsyscall_raw_syscall(fd, 0, 0, 0, 0, 0, SYS_close);
}

static long getpid() {
    return rsyscall_raw_syscall(0, 0, 0, 0, 0, 0, SYS_getpid);
}

static long tkill(int tid, int sig) {
    return rsyscall_raw_syscall(tid, sig, 0, 0, 0, 0, SYS_tkill);
}

static int myraise(int sig) {
    return tkill(getpid(), sig);
}

char getdents64_failed[] = "getdents64(fd, buf, count) failed\n";

int strtoint(const char* p) {
    int ret = 0;
    char c;
    while ((c = *p)) {
        ret *= 10;
        ret += (c - '0');
        p++;
    }
    return ret;
}

struct linux_dirent64 {
    ino64_t        d_ino;    /* 64-bit inode number */
    off64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

static int find_in_array(int wanted, int* array, int count) {
    for (int i = 0; i < count; i++) {
        if (wanted == array[i]) return 1;
    }
    return 0;
}

// Close all CLOEXEC file descriptors, excluding some in a list.
// For each open fd, we do a linear scan of the excluded array.
void rsyscall_do_cloexec(int* excluded_fds, int fd_count) {
    /* this depends on /proc, dang, but whatever */
    int dirfd = myopen("/proc/self/fd", O_DIRECTORY|O_RDONLY);
    char buf[1024];
    for (;;) {
        int const nread = getdents64(dirfd, buf, sizeof(buf));
        if (nread < 0) {
            close(dirfd);
            error(getdents64_failed, sizeof(getdents64_failed) - 1);
        } else if (nread == 0) {
            /* no more fds, we're done */
            close(dirfd);
            return;
        }
        for (int bpos = 0; bpos < nread; bpos += ((struct linux_dirent64 *) &buf[bpos])->d_reclen) {
            const struct linux_dirent64 *d = (struct linux_dirent64 *) &buf[bpos];
            if (d->d_type == DT_LNK) {
                const int fd = strtoint(d->d_name);
                if (!find_in_array(fd, excluded_fds, fd_count)) {
                    if (getfd(fd) & FD_CLOEXEC) {
                        close(fd);
                    }
                }
            }
        }
    }
}

// Signals itself with SIGSTOP, then closes a list of file descriptors.
void rsyscall_stop_then_close(int* fds_to_close, int fd_count) {
    myraise(SIGSTOP);
    for (int i = 0; i < fd_count; i++) {
        close(fds_to_close[i]);
    }
}

int rsyscall_server(const int infd, const int outfd)
{
    write(2, hello, sizeof(hello) -1);
    struct rsyscall_syscall request;
    int ret;
    for (;;) {
	ret = read_request(infd, &request);
	if (ret <= 0) return ret;
	ret = write_response(outfd, perform_syscall(request));
	if (ret <= 0) return ret;
    }
}
