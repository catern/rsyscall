#include <stdint.h>
#include <stdnoreturn.h>

struct syscall {
    int64_t sys;
    int64_t args[6];
};

/* careful: the syscall number is the last arg, to make the assembly more convenient. */
long rsyscall_raw_syscall(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long sys);
noreturn void rsyscall_server(const int infd, const int outfd);
