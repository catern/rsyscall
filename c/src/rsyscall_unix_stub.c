#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>
#include "rsyscall.h"

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

void write_null_terminated_array(int fd, char** argv)
{
    int ret;
    for (; *argv != NULL; argv++) {
        char* cur = *argv;
        size_t size = strlen(cur);
        ret = write(fd, &size, sizeof(size));
	if (ret != sizeof(size)) {
	    err(1, "write(fd=%d, &size, sizeof(size))", fd);
	}
        while (size > 0) {
            ret = write(fd, cur, size);
            if (ret < 0) {
                err(1, "write(fd=%d, cur, size=%lu)", fd, size);
            }
            size -= ret;
            cur += ret;
        }
    }
}

static int connect_unix_socket(struct sockaddr_un addr) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
	err(1, "socket");
    }
    if (connect(sockfd, &addr, sizeof(addr)) < 0) {
	err(1, "bind");
    }
    return sockfd;
}

int main(int argc, char** argv, char** envp)
{
    const char *sock_path = getenv("RSYSCALL_UNIX_STUB_SOCK_PATH");
    if (!sock_path) {
        err(1, "missing environment variable RSYSCALL_UNIX_STUB_SOCK_PATH");
    }
    const int sock_path_fd = open(sock_path, O_CLOEXEC|O_PATH);
    struct sockaddr_un pass_addr = { .sun_family = AF_UNIX, .sun_path = {}};
    snprintf(pass_addr.sun_path, sizeof(pass_addr.sun_path), "/proc/self/fd/%d", sock_path_fd);
    const int connsock = connect_unix_socket(pass_addr);

    const int nfds = 4;
    int fds[nfds];
    receive_fds(connsock, fds, nfds);
    const int syscall_fd = fds[0];
    const int data_fd = fds[1];
    const int futex_memfd = fds[2];
    const int connecting_fd = fds[3];
    size_t envp_count = 0;
    for (; envp[envp_count] != NULL; envp_count++);
    struct rsyscall_unix_stub describe = {
        .symbols = rsyscall_symbol_table(),
        .pid = getpid(),
        .syscall_fd = syscall_fd,
        .data_fd = data_fd,
        .futex_memfd = futex_memfd,
        .connecting_fd = connecting_fd,
        .argc = argc,
        .envp_count = envp_count,
    };
    int ret = write(data_fd, &describe, sizeof(describe));
    if (ret != sizeof(describe)) {
        err(1, "write(data_fd, &describe, sizeof(describe))");
    }
    write_null_terminated_array(data_fd, argv);
    write_null_terminated_array(data_fd, envp);
    rsyscall_server(syscall_fd, syscall_fd);
}
