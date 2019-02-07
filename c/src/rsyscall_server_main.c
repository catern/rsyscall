#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <stdnoreturn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "rsyscall.h"

struct options {
    int describefd;
    int infd;
    int outfd;
};

struct options parse_options(int argc, char** argv)
{
    if (argc < 3) {
        errx(1, "Usage: %s <describefd> <infd> <outfd> [passedfd [passedfd [passedfd...]]]",
             argc ? argv[0] : "rsyscall_server");
    }
    errno = 0;
    const int describefd = strtol(argv[1], NULL, 0);
    if (errno != 0) err(1, "strtol(%s)", argv[1]);
    const int infd = strtol(argv[2], NULL, 0);
    if (errno != 0) err(1, "strtol(%s)", argv[2]);
    const int outfd = strtol(argv[3], NULL, 0);
    if (errno != 0) err(1, "strtol(%s)", argv[3]);
    for (int i = 4; i < argc; i++) {
        // re-enable cloexec on all passed-in fds
        const int passedfd = strtol(argv[i], NULL, 0);
        if (errno != 0) err(1, "strtol(argv[%d] = %s)", i, argv[i]);
        if (fcntl(passedfd, F_SETFD, O_CLOEXEC) < 0) err(1, "fcntl(%d, F_SETFD, O_CLOEXEC)", passedfd);
    }
    const struct options opt = {
        .describefd = describefd,
        .infd = infd,
        .outfd = outfd,
    };
    return opt;
}

int main(int argc, char** argv)
{
    const struct options opt = parse_options(argc, argv);
    fcntl(opt.infd, F_SETFL, fcntl(opt.infd, F_GETFL) & ~O_NONBLOCK);
    fcntl(opt.outfd, F_SETFL, fcntl(opt.outfd, F_GETFL) & ~O_NONBLOCK);
    rsyscall_describe(opt.describefd);
    close(opt.describefd);
    rsyscall_server(opt.infd, opt.outfd);
}
