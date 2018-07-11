#include <sys/syscall.h>

.globl rsyscall_raw_syscall
rsyscall_raw_syscall:
	// Most of our parameters are already in the correct registers.
	// Fourth parameter for function calls is in %rcx, but should be in %r10 for system calls.
        movq %rcx, %r10
        // System call number is passed on the stack
	movq 8(%rsp), %rax
	syscall
	ret

.globl rsyscall_server_trampoline
rsyscall_server_trampoline:
	movq $2, %rdi
        pop %rsi
        pop %rdx
        movq $0, %r10
        movq $0, %r8
        movq $0, %r9
	movq $__NR_write, %rax
        syscall
        ud2
