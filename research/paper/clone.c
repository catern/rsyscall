#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sched.h>
#include <string.h>
#include <err.h>
#include <sched.h>

/* how to store these timestamps? */
/* I guess I'll put them in shared memory, and then dump at the end? */
/* uh hm. */
/* they need to be in map_shared memory I guess, so that they're inherited across the fork. */

#define NUM_RUNS 500

struct log {
        int pid;
        struct timeval pre_fork;
        struct timeval in_child;
        struct timeval in_parent;
        struct timeval after_exit;
};

enum proc_create {
        FORK,
        CLONE_FORK,
        CLONE,
};

static int do_fork(struct log *log) {
        int rc;
        rc = fork();
        if (rc == 0) {
                gettimeofday(&log->in_child, NULL);
                exit(0);
        }
        return rc;
}

static int do_clone_fork(struct log *log) {
        int rc;
        rc = syscall(SYS_clone, 0, NULL, NULL, NULL, NULL);
        if (rc == 0) {
                gettimeofday(&log->in_child, NULL);
                exit(0);
        }
        return rc;
}

static int clone_func(void *arg) {
        struct log *log = arg;
        gettimeofday(&log->in_child, NULL);
        exit(0);
}

char stack[4096];

static int do_clone(struct log *log) {
        int rc;
        rc = clone(clone_func, stack + sizeof(stack), CLONE_VM|SIGCHLD, log);
        return rc;
}

void run(enum proc_create mode, struct log *logs) {
        for (int i = 0; i < NUM_RUNS; i++) {
                struct log* const log = &logs[i];
                int rc;
                gettimeofday(&log->pre_fork, NULL);
                switch (mode) {
                case FORK: {
                        rc = do_fork(log);
                } break;
                case CLONE_FORK: {
                        rc = do_clone_fork(log);
                } break;
                case CLONE: {
                        rc = do_clone(log);
                } break;
                }
                log->pid = rc;
                gettimeofday(&log->in_parent, NULL);
                waitpid(rc, NULL, 0);
                gettimeofday(&log->after_exit, NULL);
        }
}

struct options {
        enum proc_create mode;
        int num_mappings;
};

static struct options parse_options(int argc, char **argv) {
        void usage() {
                printf("Usage: %s mode num_mappings\n", argc >= 1 ? argv[0] : "clone_bench");
                exit(1);
        }
        if (argc < 3) usage();
        enum proc_create mode;
        if (!strcmp(argv[1], "fork")) {
                mode = FORK;
        } else if (!strcmp(argv[1], "clone_fork")) {
                mode = CLONE_FORK;
        } else if (!strcmp(argv[1], "clone")) {
                mode = CLONE;
        }
        return (struct options) {
                .mode = mode,
                .num_mappings = atoi(argv[2]),
        };
}

int main(int argc, char **argv) {
        struct options opt = parse_options(argc, argv);
        /* set up memory mappings with a lot of memory */
        for (int i = 0; i < opt.num_mappings; i++) {
                char* addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                // touch the memory
                *addr = 1;
        }
        /* run the benchmark */
        struct log *logs = mmap(NULL, sizeof(*logs)*NUM_RUNS, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        // touch the memory so it faults in
        memset(logs, 0, sizeof(*logs)*NUM_RUNS);
        if (!logs) { err(1, "mmap"); }
        run(opt.mode, logs);
        run(opt.mode, logs);
        /* print out the timestamps */
        printf("pid,pre_fork_sec,pre_fork_usec,in_child_sec,in_child_usec,"
               "in_parent_sec,in_parent_usec,after_exit_sec,after_exit_usec\n");
        for (int i = 0; i < NUM_RUNS; i++) {
                printf("%d,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld\n"
                       , logs[i].pid
                       , logs[i].pre_fork.tv_sec
                       , logs[i].pre_fork.tv_usec
                       , logs[i].in_child.tv_sec
                       , logs[i].in_child.tv_usec
                       , logs[i].in_parent.tv_sec
                       , logs[i].in_parent.tv_usec
                       , logs[i].after_exit.tv_sec
                       , logs[i].after_exit.tv_usec
                      );
        }
}
