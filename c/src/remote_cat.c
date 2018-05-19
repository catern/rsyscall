#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <stdnoreturn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include "rsyscall.h"

struct remote_connection {
        int tofd;
        int fromfd;
};

struct options {
        struct remote_connection remote;
        int infd;
        int outfd;
};

int to_int(const char *s) {
        errno = 0;
        const int ret = strtol(s, NULL, 0);
        if (errno != 0) err(1, "strtol(%s)", s);
        return ret;
}

struct options parse_options(int argc, char** argv)
{
        if (argc != 3) {
                errx(1, "Usage: %s <remote_connection.to_fd> <remote_connection.from_fd>", argc ? argv[0] : "remote_cat");
        }
        struct remote_connection remote = {
                .tofd = to_int(argv[1]),
                .fromfd = to_int(argv[2]),
        };
        const struct options opt = {
                .remote = remote,
                .infd = 0,
                .outfd = 1,
        };
        return opt;
}

long rsyscall(struct remote_connection remote, long number,
              long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
        const struct syscall request = {
                .sys = number,
                .args = { arg1, arg2, arg3, arg4, arg5, arg6 },
        };
        int ret;
        ret = write(remote.tofd, &request, sizeof(request));
        if (ret < 0) err(1, "write(remote.tofd, &request, sizeof(request))");
        if (ret != sizeof(request)) errx(1, "write(remote.tofd, &request, sizeof(request)) partial write");

        struct syscall_response response;
        ret = read(remote.fromfd, &response, sizeof(response));
        if (ret < 0) err(1, "read(remote.fromfd, &response, sizeof(response)) failed");
        if (ret != sizeof(response)) err(1, "read(remote.fromfd, &response, sizeof(response)) partial read");
        errno = response.err;
        return response.ret;
}

void do_remote_splice(struct remote_connection remote, int infd, int outfd) {
        int ret = rsyscall(remote, SYS_splice, infd, 0, outfd, 0, 4096, 0);
        if (ret < 0) err(1, "remote splice(%d, NULL, %d, NULL, NULL, 4096, 0) failed", infd, outfd);
        if (ret != 4096) warnx("remote splice(%d, NULL, %d, NULL, NULL, 4096, 0) partial splice of %d", infd, outfd, ret);
        if (ret == 0) exit(0);
}

noreturn void remote_cat(struct options opt)
{
        for (;;) {
                do_remote_splice(opt.remote, opt.infd, opt.outfd);
        }
}

int main(int argc, char** argv)
{
        const struct options opt = parse_options(argc, argv);
        remote_cat(opt);
}
