#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <stdnoreturn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "rsyscall.h"

struct options {
        int infd;
        int outfd;
};

struct options parse_options(int argc, char** argv)
{
        if (argc != 3) {
                errx(1, "Usage: %s <infd> <outfd>", argc ? argv[0] : "rsyscall_server");
        }
        errno = 0;
        const int infd = strtol(argv[1], NULL, 0);
        if (errno != 0) err(1, "strtol(%s)", argv[1]);
        errno = 0;
        const int outfd = strtol(argv[2], NULL, 0);
        if (errno != 0) err(1, "strtol(%s)", argv[2]);
        const struct options opt = {
                .infd = infd,
                .outfd = outfd,
        };
        return opt;
}

struct syscall read_request(const int infd)
{
        struct syscall request;
        int ret = read(infd, &request, sizeof(request));
        if (ret < 0) err(1, "read(infd, &request, sizeof(request)) failed");
        if (ret == 0) exit(0);
        if (ret != sizeof(request)) errx(1, "read(infd, &request, sizeof(request)) partial read of %d", ret);
        return request;
}

struct syscall_response perform_syscall(struct syscall request)
{
        warnx("Got request for syscall number %d", request.sys);
        const int64_t ret = syscall(request.sys,
                                    request.args[0], request.args[1], request.args[2],
                                    request.args[3], request.args[4], request.args[5]);
        const struct syscall_response response = {
                .ret = ret,
                .err = errno,
        };
        warnx("Result was ret: %ld, errno: %d", response.ret, response.err);
        return response;
}

void write_response(const int outfd, const struct syscall_response response)
{
        int ret = write(outfd, &response, sizeof(response));
        if (ret < 0) err(1, "write(outfd, &response, sizeof(response)) failed");
        if (ret != sizeof(response)) err(1, "write(outfd, &response, sizeof(response)) partial write");
}

noreturn void rsyscall_server(const int infd, const int outfd)
{
        for (;;) {
                write_response(outfd, perform_syscall(read_request(infd)));
        }
}

int main(int argc, char** argv)
{
        const struct options opt = parse_options(argc, argv);
        fcntl(opt.infd, F_SETFL, fcntl(opt.infd, F_GETFL) & ~O_NONBLOCK);
        fcntl(opt.outfd, F_SETFL, fcntl(opt.outfd, F_GETFL) & ~O_NONBLOCK);
        rsyscall_server(opt.infd, opt.outfd);
}
