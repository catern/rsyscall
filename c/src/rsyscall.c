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
char write_failed[] = "rsyscall: write(outfd, &response, sizeof(response)) failed\n";
const int EINTR = 4;

static long write(int fd, const void *buf, size_t count) {
    return rsyscall_raw_syscall(fd, (long) buf, (long) count, 0, 0, 0, SYS_write);
}
static long read(int fd, void *buf, size_t count) {
    return rsyscall_raw_syscall(fd, (long) buf, (long) count, 0, 0, 0, SYS_read);
}

static int read_request(const int infd, struct rsyscall_syscall *request)
{
    char* buf = (char*) request;
    size_t remaining = sizeof(*request);
    while (remaining) {
        long const ret = read(infd, buf, remaining);
        if (ret == -EINTR) continue;
        if (ret < 0) {
	    write(2, read_failed, sizeof(read_failed) - 1);
	    return ret;
	}
        if (ret == 0) {
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
        if (ret == -EINTR) continue;
        if (ret < 0) {
	    write(2, write_failed, sizeof(write_failed) - 1);
	    return ret;
	}
        remaining -= ret;
        data += ret;
    }
    return 1;
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

struct rsyscall_symbol_table rsyscall_symbol_table()
{
    struct rsyscall_symbol_table table = {
        .rsyscall_server = rsyscall_server,
        .rsyscall_persistent_server = rsyscall_persistent_server,
        .rsyscall_futex_helper = rsyscall_futex_helper,
        .rsyscall_trampoline = rsyscall_trampoline,
    };
    return table;
}

static long close(int fd) {
    return rsyscall_raw_syscall(fd, 0, 0, 0, 0, 0, SYS_close);
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
        // the first fd we received is the fd to serve on
	infd = fds[0];
	outfd = fds[0];
    }
}
