#include <stdint.h>
#include <stdnoreturn.h>

struct rsyscall_syscall {
    int64_t sys;
    int64_t args[6];
};

int rsyscall_server(const int infd, const int outfd);
int rsyscall_persistent_server(int infd, int outfd, const int listensock);
void rsyscall_do_cloexec(int* excluded_fds, int fd_count);
void rsyscall_stop_then_close(int* fds_to_close, int fd_count);
void rsyscall_describe(int describefd);

/* Assembly-language routines: */
/* careful: the syscall number is the last arg, to make the assembly more convenient. */
long rsyscall_raw_syscall(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6, long sys);
/* SIGSTOPs itself when it starts up, then waits on the futex, then does exit(0). */
void rsyscall_futex_helper(void *futex_addr);
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
