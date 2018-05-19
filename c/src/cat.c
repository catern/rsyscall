#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdnoreturn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include "rsyscall.h"

struct options {
        int infd;
        int outfd;
};

struct options parse_options(int argc, char** argv)
{
        if (argc != 1) {
                errx(1, "Usage: %s", argc ? argv[0] : "cat");
        }
        const struct options opt = {
                .infd = 0,
                .outfd = 1,
        };
        return opt;
}

void do_splice(int infd, int outfd) {
        int ret = syscall(SYS_splice, infd, NULL, outfd, NULL, 4096, 0);
        if (ret < 0) err(1, "splice(%d, NULL, %d, NULL, NULL, 4096, 0) failed", infd, outfd);
        if (ret != 4096) warnx("splice(%d, NULL, %d, NULL, NULL, 4096, 0) partial splice of %d", infd, outfd, ret);
        if (ret == 0) exit(0);
}

noreturn void cat(int infd, int outfd)
{
        for (;;) {
                do_splice(infd, outfd);
        }
}

int main(int argc, char** argv)
{
        const struct options opt = parse_options(argc, argv);
        cat(opt.infd, opt.outfd);
}
