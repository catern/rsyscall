#define _GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

int main() {
    int fds[2];
    if (pipe(fds) < 0) {
	err(1, "pipe failed");
    };
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
	err(1, "pipe failed");
    };
    write(fds[1], "foo", 3);
    char buf[4096];
    struct iovec iov = { .iov_base = &buf, .iov_len = sizeof(buf) };
    printf("reading\n");
    int ret = preadv2(fds[0], &iov, 1, -1, RWF_NOWAIT);
    warn("read! got %d", ret);
    errno = 0;
    printf("reading stdin\n");
    ret = preadv2(0, &iov, 1, -1, RWF_NOWAIT);
    warn("read! got %d", ret);
    printf("reading blocking...\n");
    errno = 0;
    ret = preadv2(fds[0], &iov, 1, -1, 0);
    warn("read! got %d", ret);
}
