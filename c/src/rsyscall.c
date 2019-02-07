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

// umm
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <stdio.h>

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

static long getdents64(int fd, char* buf, unsigned int count) {
    return rsyscall_raw_syscall(fd, (long)buf, count, 0, 0, 0, SYS_getdents64);
}

static long getfd(int fd) {
    return rsyscall_raw_syscall(fd, F_GETFD, 0, 0, 0, 0, SYS_fcntl);
}

static long myopen(char* path, int flags) {
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

static int strtoint(const char* p) {
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
    /* this doesn't set O_CLOEXEC because we shouldn't be calling this function in parallel */
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
    // write(2, hello, sizeof(hello) -1);
    struct rsyscall_syscall request;
    int ret;
    for (;;) {
	ret = read_request(infd, &request);
	if (ret <= 0) return ret;
	ret = write_response(outfd, perform_syscall(request));
	if (ret <= 0) return ret;
    }
}

static void receive_fds(const int sock, int *fds, int n) {
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int) * n)];
    } cmsg;
    char waste_data;
    struct iovec io = {
        .iov_base = &waste_data,
        .iov_len = sizeof(waste_data),
    };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &io,
        .msg_iovlen = 1,
        .msg_control = &cmsg,
        .msg_controllen = sizeof(cmsg),
    };
    if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) < 0) {
        err(1, "recvmsg(sock=%d)", sock);
    }
    if (msg.msg_controllen != sizeof(cmsg)) {
        err(1, "Message has wrong controllen");
    }
    // if (cmsg.hdr.cmsg_len != sizeof(cmsg.buf)) {
    //     err(1, "Control message has wrong length");
    // }
    if (cmsg.hdr.cmsg_level != SOL_SOCKET) {
        err(1, "Control message has wrong level");
    }
    if (cmsg.hdr.cmsg_type != SCM_RIGHTS) {
        err(1, "Control message has wrong type");
    }
    memcpy(fds, CMSG_DATA(&cmsg.hdr), sizeof(int) * n);
}

char hello_persist[] = "hello world, I am the persistent syscall server!\n";

void rsyscall_describe(int describefd)
{
    dprintf(describefd, "rsyscall_server=%p\n", rsyscall_server);
    dprintf(describefd, "rsyscall_persistent_server=%p\n", rsyscall_persistent_server);
    dprintf(describefd, "rsyscall_futex_helper=%p\n", rsyscall_futex_helper);
    dprintf(describefd, "rsyscall_trampoline=%p\n", rsyscall_trampoline);
    dprintf(describefd, "rsyscall_do_cloexec=%p\n", rsyscall_do_cloexec);
    dprintf(describefd, "rsyscall_stop_then_close=%p\n", rsyscall_stop_then_close);
}

int rsyscall_persistent_server(int infd, int outfd, const int listensock)
{
    signal(SIGPIPE, SIG_IGN);
    // write(2, hello_persist, sizeof(hello_persist) -1);
    for (;;) {
	rsyscall_server(infd, outfd);
        if (shutdown(infd, SHUT_RDWR) < 0) err(1, "shutdown(infd, SHUT_RDWR)");
        if (shutdown(outfd, SHUT_RDWR) < 0) err(1, "shutdown(outfd, SHUT_RDWR)");
	const int connsock = accept4(listensock, NULL, NULL, SOCK_CLOEXEC);

	if (connsock < 0) err(1, "accept4(listensock)");
        // read the number of fds we should expect
        int nfds;
	// TODO this could be a partial read
	if (read(connsock, &nfds, sizeof(nfds)) != sizeof(nfds)) err(1, "read(connsock, &nfds)");
        // receive nfds
        int fds[nfds];
	receive_fds(connsock, fds, nfds);
	// write new fd numbers back
	// TODO this could be a partial write, whatever
	if (write(connsock, fds, sizeof(fds)) != sizeof(fds)) err(1, "write(connsock)");
	// close now-useless connsock
	if (close(connsock) < 0) err(1, "close(connsock=%d)", connsock);
        // the first two fds we received are our infd and outfd.
	infd = fds[0];
	outfd = fds[1];
    }
}
