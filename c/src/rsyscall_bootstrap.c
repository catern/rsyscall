#include "config.h"
#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdnoreturn.h>
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

static void socket_binder()
{
    struct sockaddr_un data_addr = { .sun_family = AF_UNIX, .sun_path = "./data" };
    const int datasock = listen_unix_socket(data_addr);
    struct sockaddr_un pass_addr = { .sun_family = AF_UNIX, .sun_path = "./pass" };
    const int passsock = listen_unix_socket(pass_addr);
    dprintf(1, "done\n");
    if (close(1) < 0) err(1, "close(1)");
    const int connsock = accept4(passsock, NULL, NULL, SOCK_CLOEXEC);
    if (connsock < 0) err(1, "accept4(passsock)");
    if (close(passsock) < 0) err(1, "close(passsock)");
    if (unlink("./pass") < 0) err(1, "unlink");
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsg = {
        .hdr = {
            .cmsg_len = CMSG_LEN(sizeof(int)),
            .cmsg_level = SOL_SOCKET,
            .cmsg_type = SCM_RIGHTS,
        },
    };
    memcpy(CMSG_DATA(&cmsg.hdr), &datasock, sizeof(datasock));
    char waste_data = 0;
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
    if (sendmsg(connsock, &msg, 0) < 0) err(1, "sendmsg(connsock=%d, {msg={datasock=%d}})", connsock, datasock);
    if (close(connsock) < 0) err(1, "close(connsock)");
    if (close(datasock) < 0) err(1, "close(datasock)");
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

static int accept_on(const int listening_sock) {
    const int connsock = accept4(listening_sock, NULL, NULL, SOCK_CLOEXEC);
    if (connsock < 0) err(1, "accept4(listening_sock=%d)", listening_sock);
    return connsock;
}

noreturn static void bootstrap(char** envp)
{
    struct sockaddr_un pass_addr = { .sun_family = AF_UNIX, .sun_path = "./pass" };
    const int pass_conn_sock = connect_unix_socket(pass_addr);
    // receive listening socket
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
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
    if (recvmsg(pass_conn_sock, &msg, 0) < 0) {
        err(1, "recvmsg(connsock=%d)", pass_conn_sock);
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
    int listening_sock;
    memcpy(&listening_sock, CMSG_DATA(&cmsg.hdr), sizeof(listening_sock));
    // accept connections
    const int bootstrap_describe_sock = accept_on(listening_sock);
    const int syscall_sock = accept_on(listening_sock);
    const int data_sock = accept_on(listening_sock);
    struct rsyscall_bootstrap describe = {
        .symbols = rsyscall_symbol_table(),
        .pid = getpid(),
        .listening_sock = listening_sock,
        .syscall_sock = syscall_sock,
        .data_sock = data_sock,
        .envp_count = strlen(envp),
    };
    int ret = write(bootstrap_describe_sock, &describe, sizeof(describe));
    if (ret != sizeof(describe)) {
        err(1, "write(bootstrap_describe_sock, &describe, sizeof(describe))");
    }
    for (; *envp != NULL; envp++) {
        size_t size = strlen(cur);
        write(bootstrap_describe_sock, &size, sizeof(size));
        char* cur = *envp;
        while (size > 0) {
            ret = write(bootstrap_describe_sock, cur, size);
            if (ret < 0) {
                err(1, "write(bootstrap_describe_sock=%d, cur, size=%lu)", bootstrap_describe_sock, size);
            }
            size -= ret;
            cur += ret;
        }
    }
    if (close(bootstrap_describe_sock) < 0) {
        err(1, "close(bootstrap_describe_sock=%d)", bootstrap_describe_sock);
    }
    rsyscall_server(syscall_sock, syscall_sock);
}

int main(int argc, char** argv, char** envp)
{
    if (argc < 2) errx(1, "usage: %s <type>", argv[0]);
    const char* type = argv[1];
    if (strcmp(type, "rsyscall") == 0) {
        bootstrap(envp);
    } else if (strcmp(type, "socket") == 0) {
        socket_binder();
    } else {
        errx(1, "unknown type %s", type);
    }
}
