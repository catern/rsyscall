#define __ASSEMBLY__
#include <sys/syscall.h>
#include <asm/signal.h>

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
	// call prctl(PR_SET_PDEATHSIG, SIGTERM) so we die when our parent does
	movq $1, %rdi
        movq $SIGKILL, %rsi
	movq $__NR_prctl, %rax
	syscall
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
	// exit thread cleanly
	movq $0, %rdi
        movq $0, %rsi
	movq $__NR_exit, %rax
        syscall

.globl rsyscall_futex_helper
rsyscall_futex_helper:
	// safely stash the
	movq %rdi, %r8 // futex address and
	movq %rsi, %r9 // futex value.
	// get my tid
	movq $__NR_gettid, %rax
	syscall
	// SIGSTOP myself
	movq %rax, %rdi
        movq $SIGSTOP, %rsi
	movq $__NR_tkill, %rax
	syscall
	// futex(futex_address, FUTEX_WAIT, futex_value)
	movq %r8, %rdi
	movq $0, %rsi    // FUTEX_WAIT == 0
	movq %r9, %rdx
	movq $__NR_futex, %rax
	syscall
	// exit(0)
	movq $0, %rdi
	movq $__NR_exit, %rax
        syscall
