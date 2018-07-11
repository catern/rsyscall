#include <stdint.h>
#include <stdnoreturn.h>

struct syscall {
    int64_t sys;
    int64_t args[6];
};

/* careful: the syscall number is the last arg, to make the assembly more convenient. */
long rsyscall_raw_syscall(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long sys);
noreturn void rsyscall_server(const int infd, const int outfd);

/* A trampoline useful when used with clone to call arbitrary functions. */
void rsyscall_trampoline(void);

/* The stack should be set up as follows to use rsyscall_trampoline. */
struct rsyscall_trampoline_stack {
    int64_t rdi;
    int64_t rsi;
    int64_t rdx;
    int64_t rcx;
    int64_t r8;
    int64_t r9;
    void* function;
};
