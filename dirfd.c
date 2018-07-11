#define _GNU_SOURCE
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/un.h>

int main() {
    int ret;
    int dirfd;
    dirfd = ret = open("dir", O_DIRECTORY);
    if (ret < 0) err(1, "open");
    char buf[4096];
    ret = read(dirfd, buf, sizeof(buf));
    if (ret < 0) err(1, "read");
}
