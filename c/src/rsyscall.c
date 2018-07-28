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
char read_failed[] = "read(infd, &request, sizeof(request)) failed\n";
char read_eof[] = "read(infd, &request, sizeof(request)) returned EOF\n";
char write_failed[] = "write(outfd, &response, sizeof(response)) failed\n";

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

static struct rsyscall_syscall read_request(const int infd)
{
    struct rsyscall_syscall request;
    char* buf = (char*) &request;
    size_t remaining = sizeof(request);
    while (remaining) {
        long const ret = read(infd, buf, remaining);
        if (ret < 0) error(read_failed, sizeof(read_failed) - 1);
        if (ret == 0) {
            write(2, read_eof, sizeof(read_eof) - 1);
            exit(0);
        }
        remaining -= ret;
        buf += ret;
    }
    return request;
}

static int64_t perform_syscall(struct rsyscall_syscall request)
{
    return rsyscall_raw_syscall(request.args[0], request.args[1], request.args[2],
                       request.args[3], request.args[4], request.args[5],
                       request.sys);
}

static void write_response(const int outfd, const int64_t response)
{
    char* data = (char*) &response;
    size_t remaining = sizeof(response);
    while (remaining) {
        long const ret = write(outfd, data, remaining);
        if (ret < 0) error(write_failed, sizeof(write_failed) - 1);
        remaining -= ret;
        data += ret;
    }
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

long close(int fd) {
    return rsyscall_raw_syscall(fd, 0, 0, 0, 0, 0, SYS_close);
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

/* Close all CLOEXEC file descriptors */
/* We should add a CLONE_DO_CLOEXEC flag to replace this */
/* hmm we want to exclude fds in a list */
/* maybe we'll make a bitset? */
/* I guess we'll just do a linear scan of the excluded array we receive */
void rsyscall_do_cloexec(int* excluded_fds, int fd_count) {
    /* this depends on /proc, dang, but whatever */
    int dirfd = myopen("/proc/self/fd", O_DIRECTORY|O_RDONLY);
    char buf[1024];
    for (;;) {
        int const nread = getdents64(dirfd, buf, sizeof(buf));
        if (nread < 0) {
            error(getdents64_failed, sizeof(getdents64_failed) - 1);
        } else if (nread == 0) {
            /* no more fds, we're done */
            return;
        }
        for (int bpos = 0; bpos < nread;) {
            const struct linux_dirent64 *d = (struct linux_dirent64 *) &buf[bpos];
            if (d->d_type == DT_LNK) {
                const int fd = strtoint(d->d_name);
                for (int i = 0; i < fd_count; i++) {
                    if (fd == excluded_fds[i]) goto skip;
                }
                if (getfd(fd) & FD_CLOEXEC) {
                    close(fd);
                }
            skip:
                ;
            }
            bpos += d->d_reclen;
        }
    }
}

noreturn void rsyscall_server(const int infd, const int outfd, const int ppid)
{
    write(2, hello, sizeof(hello) -1);
    for (;;) {
        write_response(outfd, perform_syscall(read_request(infd)));
    }
}
