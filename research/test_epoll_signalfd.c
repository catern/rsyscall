#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

int try(int ret) {
    if (ret < 0) err(EXIT_FAILURE, NULL);
    return ret;
}

void parent(long epfd) {
    printf("parent pid is %d\n", getpid());
    sleep(1);
    printf("raising in parent\n");
    // try(kill(getpid(), SIGPIPE));
    printf("calling epoll_wait\n");
    struct epoll_event receive_event;
    int events = try(epoll_wait(epfd, &receive_event, 1, -1));
    printf("got %d events back from epoll_wait\n", events);
}

int child(void *arg) {
    printf("child pid is %d\n", getpid());
    long epfd = (long) arg;
    sigset_t mask = {};
    try(sigaddset(&mask, SIGPIPE));
    try(sigprocmask(SIG_BLOCK, &mask, NULL));
    int sigfd = try(signalfd(-1, &mask, SFD_NONBLOCK));
    struct epoll_event monitor_event = { .events = EPOLLIN, .data = 0 };
    try(epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &monitor_event));
    printf("signalfd added to epfd\n");
    printf("raising in child\n");
    // try(kill(getpid(), SIGPIPE));
    sleep(100);
}

int main() {
    long epfd = try(epoll_create1(0));
    sigset_t mask = {};
    void *stack = malloc(4096) + 4096;
    try(sigaddset(&mask, SIGPIPE));
    try(sigprocmask(SIG_BLOCK, &mask, NULL));
    try(clone(child, stack, CLONE_VM|CLONE_SIGHAND, (void *) epfd));
    parent(epfd);
}
