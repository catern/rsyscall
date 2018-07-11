.globl rsyscall_raw_syscall
rsyscall_raw_syscall:
	// Most of our parameters are already in the correct registers.
	// Fourth parameter for function calls is in %rcx, but should be in %r10 for system calls.
        movq %rcx, %r10
        // System call number is passed on the stack
	movq 16(%rsp), %rax
	syscall
	ret
