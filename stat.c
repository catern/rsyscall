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

int main() {
    struct stat statbuf = {};
    int ret = fstatat(AT_FDCWD, "stat.c", &statbuf, 0);
    if (ret != 0) {
	err(1, "fstatat");
    }
}
