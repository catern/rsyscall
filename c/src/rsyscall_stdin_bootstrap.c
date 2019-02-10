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
    dprintf(data_fd, "pid=%d\n", getpid());
    dprintf(data_fd, "syscall_fd=%d\n", syscall_fd);
    dprintf(data_fd, "data_fd=%d\n", data_fd);
    dprintf(data_fd, "futex_memfd=%d\n", futex_memfd);
    dprintf(data_fd, "environ=%d\n", strlen(envp));
    for (; *envp != NULL; envp++) {
        // gotta use netstrings here because environment variables can contain newlines
        char* cur = *envp;
        size_t size = strlen(cur);
        dprintf(data_fd, "%lu:", size);
        while (size > 0) {
            int ret = write(data_fd, cur, size);
            if (ret < 0) {
                err(1, "write(data_fd=%d, cur, size=%lu)", data_fd, size);
            }
            size -= ret;
            cur += ret;
        }
        if (write(data_fd, ",", 1) != 1) {
            err(1, "write(data_fd=%d, \",\", 1)", data_fd);
        }
    }
    rsyscall_describe(data_fd);
    rsyscall_server(syscall_fd, syscall_fd);
}
