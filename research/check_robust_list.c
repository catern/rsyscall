#define _GNU_SOURCE
#include <linux/futex.h>
#include <sys/types.h>
#include <syscall.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    if (argc != 2) errx(1, "usage: check_robust_list <pid>");
    errno = 0;
    const int pid = strtol(argv[1], NULL, 0);
    if (errno != 0) err(1, "strtol(%s)", argv[1]);
    struct robust_list_head *headptr;
    size_t lenptr;
    int ret = syscall(SYS_get_robust_list, pid, &headptr, &lenptr);
    if (ret != 0) err(1, "get_robust_list(%d)", pid);
    printf("robust_list_head: %p\n", headptr);
}
