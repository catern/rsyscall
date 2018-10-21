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

int open_private_dir() {
    char *tmpdir;
    tmpdir = getenv("XDG_RUNTIME_DIR");
    if (!tmpdir) tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    char *template;
    if (asprintf(&template, "%s/XXXXXX", tmpdir) < 0) {
	err(1, "asprintf");
    };
    const char *dirname = mkdtemp(template);
    if (!dirname) {
	err(1, "mkdtemp");
    }
    const int dirfd = open(dirname, O_DIRECTORY|O_CLOEXEC);
    if (dirfd < 0) {
	err(1, "open");
    }
    free(template);
    return dirfd;
}

int bind_unix_socket(int dirfd, const char *name) {
    struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = {} };
    int ret = snprintf(addr.sun_path, sizeof(addr.sun_path), "/proc/self/fd/%d/%s", dirfd, name);
    if (ret < 0) {
	err(1, "snprintf");
    }
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
	err(1, "socket");
    }
    if (bind(sockfd, addr, sizeof(addr)) < 0) {
	err(1, "bind");
    }
    return sockfd;
}

int main(int argc, char** argv)
{
    const int dirfd = open_private_dir();
    const int datasock = bind_unix_socket(dirfd, "data");
    const int passsock = bind_unix_socket(dirfd, "pass");
}
