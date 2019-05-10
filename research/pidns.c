#define _GNU_SOURCE
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>

int child(void *arg) {
    sleep(999);
    return 0;
}

int main(int argc, char **argv) {
    int ret;
    bool should_use_newpid = false;
    if (argc > 1) {
        should_use_newpid = true;
    }
    sigset_t sigset;
    ret = sigaddset(&sigset, SIGCHLD);
    if (ret < 0) err(1, "sigaddset");
    ret = sigprocmask(SIG_BLOCK, &sigset, NULL);
    if (ret < 0) err(1, "sigprocmask");
    int flags = CLONE_VM|CLONE_SIGHAND|CLONE_NEWUSER|SIGCHLD;
    if (should_use_newpid) {
        printf("using CLONE_NEWPID\n");
        flags |= CLONE_NEWPID;
    } else {
        printf("not using CLONE_NEWPID\n");
    }
    printf("pid: %d\n", getpid());
    int child_pid = ret = clone(child, malloc(4096), flags, 0);
    if (ret < 0) err(1, "clone");
    printf("child_pid: %d\n", child_pid);
    ret = kill(child_pid, SIGKILL);
    if (ret < 0) err(1, "kill");
    int signum;
    printf("waiting for signal\n");
    ret = sigwait(&sigset, &signum);
    if (ret < 0) err(1, "sigwait");
    printf("got signal: %d\n", signum);
}
