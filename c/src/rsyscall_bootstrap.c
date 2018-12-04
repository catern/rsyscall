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
    // no cloexec because we want to pass these down
    const int connsock = accept4(listening_sock, NULL, NULL, 0);
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
    const int describe_sock = accept_on(listening_sock);
    const int syscall_sock = accept_on(listening_sock);
    const int data_sock = accept_on(listening_sock);
    dprintf(bootstrap_describe_sock, "listening_sock=%d\n", listening_sock);
    dprintf(bootstrap_describe_sock, "syscall_sock=%d\n", syscall_sock);
    dprintf(bootstrap_describe_sock, "data_sock=%d\n", data_sock);
    dprintf(bootstrap_describe_sock, "environ\n");
    for (; *envp != NULL; envp++) {
        // gotta use netstrings here because environment variables can contain newlines
        char* cur = *envp;
        size_t size = strlen(cur);
        dprintf(bootstrap_describe_sock, "%lu:", size);
        while (size > 0) {
            int ret = write(bootstrap_describe_sock, cur, size);
            if (ret < 0) {
                err(1, "write(bootstrap_describe_sock=%d, cur, size=%lu)", bootstrap_describe_sock, size);
            }
            size -= ret;
            cur += ret;
        }
        if (write(bootstrap_describe_sock, ",", 1) != 1) {
            err(1, "write(bootstrap_describe_sock=%d, \",\", 1)", bootstrap_describe_sock);
        }
    }
    if (close(bootstrap_describe_sock) < 0) {
        err(1, "close(bootstrap_describe_sock=%d)", bootstrap_describe_sock);
    }
    char describe_sock_str[16];
    if (snprintf(describe_sock_str, sizeof(describe_sock_str), "%d", describe_sock) < 0) {
        err(1, "snprintf(describe_sock_str, describe_sock=%d)", describe_sock);
    }
    char syscall_sock_str[16];
    if (snprintf(syscall_sock_str, sizeof(syscall_sock_str), "%d", syscall_sock) < 0) {
        err(1, "snprintf(syscall_sock_str, syscall_sock=%d)", syscall_sock);
    }
    char data_sock_str[16];
    if (snprintf(data_sock_str, sizeof(data_sock_str), "%d", data_sock) < 0) {
        err(1, "snprintf(data_sock_str, data_sock=%d)", data_sock);
    }
    // TODO we should just call the rsyscall_server function directly here
    char* new_argv[] = {
        "rsyscall-server",
        // the actual arguments
        describe_sock_str, syscall_sock_str, syscall_sock_str,
        // passedfd arguments
        describe_sock_str, syscall_sock_str, data_sock_str,
        0,
    };
    execve(RSYSCALL_SERVER_PATH, new_argv, envp);
    err(1, "exec(" RSYSCALL_SERVER_PATH ", new_argv=%p, envp=%p)", new_argv, envp);
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
