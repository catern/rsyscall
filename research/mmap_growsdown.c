#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

void touch(char* p) {
    printf("writing to %p\n", p);
    strcpy(p, "hello world");
    printf("written data: %s\n", p);
};

int main() {
    char *buf, *p;
    buf = mmap((void *) 0x80000000, 4096, PROT_READ|PROT_WRITE,
	     MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN, -1, 0);
    printf("addr: %p\n", buf);

    // man mmap says, when MAP_GROWSDOWN is set: "The return address
    // is one page lower than the memory area that is actually created
    // in the process's virtual address space."

    // buf, therefore is one page lower than our mapping: so our mapping is buf + 4096.
    // So this should succeed.
    touch(buf + 4096 + 128);

    // man mmap says, when MAP_GROWSDOWN is set: "Touching an address
    // in the "guard" page below the mapping will cause the mapping to
    // grow by a page.
    // So this should grow the mapping:
    touch(buf + 1024);
    // and so this should succeed.
    touch(buf - 1024);
}
