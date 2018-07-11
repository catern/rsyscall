#include <stdint.h>

struct syscall {
    int64_t sys;
    int64_t args[6];
};

noreturn void rsyscall_server(const int infd, const int outfd);
