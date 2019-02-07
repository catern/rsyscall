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

void bootstrap(int connsock)
{
    // read the number of fds we should expect
    int nfds;
    // TODO this could be a partial read
    if (read(connsock, &nfds, sizeof(nfds)) != sizeof(nfds)) err(1, "read(connsock, &nfds)");
    if (nfds < 3) err(1, "expect to read at least three fds");
    // receive nfds
    int fds[nfds];
    receive_fds(connsock, fds, nfds);
    // write new fd numbers back
    // TODO this could be a partial write, whatever
    if (write(connsock, fds, sizeof(fds)) != sizeof(fds)) err(1, "write(connsock)");

    // the first three fds are special
    rsyscall_describe(fds[0]);
    close(fds[0]);
    rsyscall_server(fds[1], fds[2]);
}

int main(int argc, char** argv)
{
    if (argc != 1) errx(1, "usage: %s", argv[0]);
    bootstrap(0);
}
