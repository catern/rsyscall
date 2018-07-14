#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <stdnoreturn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "rsyscall.h"

struct remote_connection {
        int tofd;
        int fromfd;
};

struct remote_fd {
        struct remote_connection remote;
        int fd;
};

struct to_remote_pipe {
        int local_fd;
        struct remote_fd remote_fd;
};

struct options {
        int infd;
        struct to_remote_pipe pipe;
        struct remote_fd outfd;
};

int to_int(const char *s) {
        errno = 0;
        const int to_fd = strtol(argv[1], NULL, 0);
        if (errno != 0) err(1, "strtol(%s)", argv[1]);
}

struct remote parse_options(int argc, char** argv)
{
        if (argc != 5) {
                errx(1, "Usage: %s <remote_connection.to_fd> <remote_connection.from_fd>"
                     " <to_remote_pipe.local_fd> <to_remote_pipe.remote_fd>",
                     argc ? argv[0] : "in_to_remote_out");
        }
        struct remote_connection remote = {
                .tofd = to_int(argv[1]),
                .fromfd = to_int(argv[2]),
        };
        struct to_remote_pipe pipe = {
                .local_fd = to_int(argv[3]),
                .remote_fd = {
                        .remote = remote,
                        .fd = to_int(argv[4]),
                },
        };
        const struct options opt = {
                .infd = 0,
                .pipe = pipe,
                .outfd = {
                        .remote = remote,
                        .fd = 1,
                },
        };
        return opt;
}

struct rsyscall_syscall read_request(const int to_fd)
{
        struct rsyscall_syscall request;
        int ret = recv(to_fd, &request, sizeof(request), MSG_WAITALL);
        if (ret < 0) err(1, "recv(to_fd, &request, sizeof(request), MSG_WAITALL) failed");
        if (ret != sizeof(request)) err(1, "recv(to_fd, &request, sizeof(request), MSG_WAITALL) partial read");
        return request;
}

struct rsyscall_syscall_response perform_syscall(struct rsyscall_syscall request)
{
        const int64_t ret = syscall(request.sys,
                                    request.args[0], request.args[1], request.args[2],
                                    request.args[3], request.args[4], request.args[5]);
        const struct rsyscall_syscall_response response = {
                .ret = ret,
                .err = errno,
        };
        return response;
}

void write_response(const int from_fd, const struct rsyscall_syscall_response response)
{
        int ret = write(from_fd, &response, sizeof(response));
        if (ret < 0) err(1, "write(from_fd, &response, sizeof(response)) failed");
        if (ret != sizeof(response)) err(1, "write(from_fd, &response, sizeof(response)) partial write");
}

struct promise {
        struct remote_connection remote;
};

struct promise start_remote_splice(struct remote_fd infd, struct remote_fd outfd) {
        /* make splice syscall request */
        /* write it out boom */
}

void do_local_splice(int infd, int outfd) {
        /* do a local splice for the same size */
}

void finish_remote_splice(struct promise promise) {
        /* read the response off, validate that it's the right size and stuff */
}

noreturn void in_to_remote_out(struct options opt)
{
        for (;;) {
                struct promise promise = start_remote_splice(opt.pipe.remote_fd, opt.outfd);
                do_local_splice(opt.infd, opt.pipe.local_fd);
                finish_remote_splice(promise);
        }
}

int main(int argc, char** argv)
{
        const struct options opt = parse_options(argc, argv);
        rsyscall_server(opt.remote, .to_fd, opt.from_fd);
}
