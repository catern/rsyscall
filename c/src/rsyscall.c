#define _GNU_SOURCE
#include <stddef.h>
#include <sys/syscall.h>
#include <stdnoreturn.h>
#include "rsyscall.h"

struct options {
        int infd;
        int outfd;
};

char hello[] = "hello world, I am the syscall server!\n";
char read_failed[] = "read(infd, &request, sizeof(request)) failed\n";
char read_eof[] = "read(infd, &request, sizeof(request)) returned EOF\n";
char write_failed[] = "write(outfd, &response, sizeof(response)) failed\n";

static long write(int fd, const void *buf, size_t count) {
    return rsyscall_raw_syscall(fd, (long) buf, (long) count, 0, 0, 0, SYS_write);
}
static long read(int fd, void *buf, size_t count) {
    return rsyscall_raw_syscall(fd, (long) buf, (long) count, 0, 0, 0, SYS_read);
}

static void exit(int status) {
    rsyscall_raw_syscall(status, 0, 0, 0, 0, 0, SYS_exit);
}

static void error(char* msg, size_t msgsize) {
    write(2, msg, msgsize);
    exit(1);
}

static struct rsyscall_syscall read_request(const int infd)
{
    struct rsyscall_syscall request;
    char* buf = (char*) &request;
    size_t remaining = sizeof(request);
    while (remaining) {
        long const ret = read(infd, buf, remaining);
        if (ret < 0) error(read_failed, sizeof(read_failed) - 1);
        if (ret == 0) {
            write(2, read_eof, sizeof(read_eof) - 1);
            exit(0);
        }
        remaining -= ret;
        buf += ret;
    }
    return request;
}

static int64_t perform_syscall(struct rsyscall_syscall request)
{
    return rsyscall_raw_syscall(request.args[0], request.args[1], request.args[2],
                       request.args[3], request.args[4], request.args[5],
                       request.sys);
}

static void write_response(const int outfd, const int64_t response)
{
    char* data = (char*) &response;
    size_t remaining = sizeof(response);
    while (remaining) {
        long const ret = write(outfd, data, remaining);
        if (ret < 0) error(write_failed, sizeof(write_failed) - 1);
        remaining -= ret;
        data += ret;
    }
}

noreturn void rsyscall_server(const int infd, const int outfd)
{
    write(2, hello, sizeof(hello) -1);
    for (;;) {
        write_response(outfd, perform_syscall(read_request(infd)));
    }
}
