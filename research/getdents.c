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
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

struct linux_dirent64 {
    ino64_t        d_ino;    /* 64-bit inode number */
    off64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};

int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    return syscall(SYS_getdents64, fd, dirp, count);
};

void print_dirent(struct linux_dirent64 *p) {
    warnx("dirent: inode %lu off %lu reclen %d type %d", p->d_ino, p->d_off, p->d_reclen, p->d_type);
    warnx("dirent: name %s", p->d_name);
}

int main() {
    int ret = open(".", O_DIRECTORY);
    if (ret < 0) err(1, "open");
    char buf[4096];
    ret = getdents64(ret, (struct linux_dirent64 *) buf, sizeof(buf));
    if (ret < 0) err(1, "getdents");
    warnx("getdents result %d", ret);
    struct linux_dirent64 *cur;
    char *curp = buf;
    int i = 0;
    while (curp < (buf+ret)) {
	cur = (struct linux_dirent64 *) curp;
	print_dirent(cur);
	curp = curp + cur->d_reclen;
	i++;
	if (i > 30) break;
    }
}
