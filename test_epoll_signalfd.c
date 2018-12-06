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
	sleep(1);
	printf("raising in parent and epoll_waiting\n");
	try(kill(getpid(), SIGPIPE));
	// try(raise(SIGPIPE));
	printf("sleeping in parent\n");
	sleep(5);
	printf("waiting now in parent\n");
	struct epoll_event receive_event;
	int events = try(epoll_wait(epfd, &receive_event, 1, -1));
	printf("got %d events back from epoll_wait\n", events);
	printf("sleeping in parent\n");
	sleep(30);
	printf("waiting now in parent\n");
	events = try(epoll_wait(epfd, &receive_event, 1, -1));
    } else {
	int sigfd = try(signalfd(-1, &mask, SFD_NONBLOCK));
	struct epoll_event monitor_event = { .events = EPOLLIN, .data = 0 };
	try(epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &monitor_event));
	printf("signalfd added to epfd\n");
	sleep(2);
	printf("raising in child\n");
	try(kill(getpid(), SIGPIPE));
	sleep(1);
	// try(raise(SIGPIPE));
	char buf[4096];
	ret = try(read(sigfd, buf, sizeof(buf)));
	printf("got %d bytes from read\n", ret);
	ret = read(sigfd, buf, sizeof(buf));
	printf("got %d bytes from read\n", ret);
	sleep(10);
    }
}
