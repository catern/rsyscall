#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

int main() {
        int rc;
        rc = fork();
        if (rc == 0) { execlp("foo", "foo", "bar", "baz", NULL); }
        else { wait(NULL); }
        rc = fork();
        if (rc == 0) { execlp("whatever", "whatever", "quux", NULL); }
        else { wait(NULL); }
        return 0;
}
