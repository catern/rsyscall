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
    int sockfd;
    sockfd = ret = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ret < 0) err(1, "socket");

    struct sockaddr_un sockpath = {
	.sun_family = AF_UNIX,
	.sun_path = {},
    };
    strcpy(sockpath.sun_path, "hello.sock");
    ret = bind(sockfd, &sockpath, sizeof(sockpath));
    if (ret < 0) err(1, "bind");
    ret = listen(sockfd, 10);
    if (ret < 0) err(1, "listen");

    ret = open("hello.sock", O_RDWR);
    if (ret < 0) err(1, "open %d", errno);
}
