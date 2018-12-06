#include <signal.h>
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

int main() {
    int ret;
    int epfd = try(epoll_create1(0));
    sigset_t mask = {};
    try(sigaddset(&mask, SIGPIPE));
    try(sigprocmask(SIG_BLOCK, &mask, NULL));
    pid_t pid = try(fork());
    if (pid > 0) {
	printf("child pid is %d\n", pid);
	printf("parent pid is %d\n", getpid());
	try(kill(getpid(), SIGPIPE));
	sleep(1);
	printf("raising in parent and epoll_waiting\n");
	printf("waiting now in parent\n");
	struct epoll_event receive_event;
	int events = try(epoll_wait(epfd, &receive_event, 1, -1));
	printf("got %d events back from epoll_wait\n", events);
    } else {
	int sigfd = try(signalfd(-1, &mask, SFD_NONBLOCK));
	struct epoll_event monitor_event = { .events = EPOLLIN, .data = 0 };
	try(epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &monitor_event));
	printf("raising in child\n");
	try(kill(getpid(), SIGPIPE));
    }
}
