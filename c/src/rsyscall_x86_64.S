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
	// immediately set PR_SET_PDEATHSIG to SIGKILL to minimize the race
        // condition where our parent could die early
	movq $1, %rdi // PR_SET_PDEATHSIG
        movq $9, %rsi // SIGKILL
	movq $__NR_prctl, %rax
        syscall // ignore return value
	// load argument registers from the stack
	pop %rdi
        pop %rsi
	pop %rdx
        pop %rcx
        pop %r8
        pop %r9
	// load function to call from stack
	pop %rax
	// call function; we assume we're aligned properly
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
	// SIGTERM myself so signal handlers can fire
	movq %rax, %rdi
        movq $15, %rsi
	movq $__NR_kill, %rax
	syscall
	// If we were created with CLONE_SIGHAND, and we inherited a signal mask
        // masking out SIGTERM, then the kill may be processed in another task.
        // So, also exit thread cleanly just in case.
	movq $0, %rdi
        movq $0, %rsi
	movq $__NR_exit, %rax
        syscall

.globl rsyscall_futex_helper
rsyscall_futex_helper:
	// safely stash the futex address
	movq %rdi, %r9
	// get my tid
	movq $__NR_gettid, %rax
	syscall
	// SIGSTOP myself
	movq %rax, %rdi
        movq $19, %rsi
	movq $__NR_tkill, %rax
	syscall
	// futex(futex_address, FUTEX_WAIT, 1)
	movq %r9, %rdi
	movq $0, %rsi    // FUTEX_WAIT == 0
	movq $1, %rdx
	movq $__NR_futex, %rax
	syscall
	// exit(0)
	movq $0, %rdi
	movq $__NR_exit, %rax
        syscall
