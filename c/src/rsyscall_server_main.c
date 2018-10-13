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
        const int outfd = strtol(argv[2], NULL, 0);
        if (errno != 0) err(1, "strtol(%s)", argv[2]);
        const struct options opt = {
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
        rsyscall_server(opt.infd, opt.outfd);
}
