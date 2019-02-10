#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
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

int main(int argc, char** argv, char** envp)
{
    if (argc != 1) errx(1, "usage: %s", argv[0]);
    const int connsock = 0;
    const int nfds = 3;
    int fds[nfds];
    receive_fds(connsock, fds, nfds);
    const int syscall_fd = fds[0];
    const int data_fd = fds[1];
    const int futex_memfd = fds[2];
    size_t envp_count = 0;
    for (; envp[envp_count] != NULL; envp_count++);
    struct rsyscall_stdin_bootstrap describe = {
        .symbols = rsyscall_symbol_table(),
        .pid = getpid(),
        .syscall_fd = syscall_fd,
        .data_fd = data_fd,
        .futex_memfd = futex_memfd,
        .envp_count = envp_count,
    };
    int ret = write(data_fd, &describe, sizeof(describe));
    if (ret != sizeof(describe)) {
        err(1, "write(data_fd, &describe, sizeof(describe))");
    }
    for (; *envp != NULL; envp++) {
        char* cur = *envp;
        size_t size = strlen(cur);
        ret = write(data_fd, &size, sizeof(size));
	if (ret != sizeof(size)) {
	    err(1, "write(data_fd, &size, sizeof(size))");
	}
        while (size > 0) {
            ret = write(data_fd, cur, size);
            if (ret < 0) {
                err(1, "write(data_fd=%d, cur, size=%lu)", data_fd, size);
            }
            size -= ret;
            cur += ret;
        }
    }
    rsyscall_server(syscall_fd, syscall_fd);
}
