#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include "rsyscall.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

static int listen_unix_socket(const struct sockaddr_un addr) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
	err(1, "socket");
    }
    if (bind(sockfd, &addr, sizeof(addr)) < 0) {
	err(1, "bind");
    }
    if (listen(sockfd, 10) < 0) {
	err(1, "listen");
    }
    return sockfd;
}

struct fdpair {
    int in;
    int out;
};

static struct fdpair receive_fdpair(const int sock) {
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int) * 2)];
    } cmsg = {};
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
    if (recvmsg(sock, &msg, 0) < 0) {
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
    int syscallfds[2];
    memcpy(&syscallfds, CMSG_DATA(&cmsg.hdr), sizeof(syscallfds));
    return (struct fdpair) { .in = syscallfds[0], .out = syscallfds[1] };
}

int main() {
    // we only support one connection at a time
    // which nicely simplifies things, actually, since we can just wait on the cloned thread.
    struct sockaddr_un pass_addr = { .sun_family = AF_UNIX, .sun_path = "./pass" };
    const int passsock = listen_unix_socket(pass_addr);
    for (;;) {
	// accept connection
	const int connsock = accept4(passsock, NULL, NULL, SOCK_CLOEXEC);
	if (connsock < 0) err(1, "accept4(passsock)");
	// receive listening socket
	struct fdpair fds = receive_fdpair(connsock);
	// close now-useless connsock
	if (close(connsock) < 0) err(1, "close(connsock=%d)", connsock);
	// loop in rsyscall server until it exits, we don't care why
	rsyscall_server(fds.in, fds.out);
	// close the fds
	if (close(fds.in) < 0) err(1, "close(fds.in=%d)", fds.in);
	if (close(fds.out) < 0) err(1, "close(fds.in=%d)", fds.out);
    }
}
