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

.globl rsyscall_trampoline
rsyscall_trampoline:
	// load argument registers from the stack
	pop %rdi
        pop %rsi
	pop %rdx
        pop %rcx
        pop %r8
        pop %r9
	// load function to call from stack
	pop %rax
	// call function
	call *%rax
	// store return value on stack
	push %rax
	// get my tid
	movq $0, %rdi
        movq $0, %rsi
	movq $0, %rdx
        movq $0, %r10
        movq $0, %r8
        movq $0, %r9
	movq $__NR_gettid, %rax
	syscall
	// SIGTERM myself
	movq %rax, %rdi
        movq $15, %rsi
	movq $__NR_tkill, %rax
	syscall
	// should not return, but if it does:
	// exit thread uncleanly
	movq $1, %rdi
        movq $0, %rsi
	movq $__NR_exit, %rax
        syscall
