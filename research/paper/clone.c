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

/* how to store these timestamps? */
/* I guess I'll put them in shared memory, and then dump at the end? */
/* uh hm. */
/* they need to be in map_shared memory I guess, so that they're inherited across the fork. */

#define NUM_RUNS 1000

struct log {
        int pid;
        struct timeval pre_fork;
        struct timeval in_child;
        struct timeval in_parent;
        struct timeval after_exit;
};


void run(struct log *logs) {
        for (int i = 0; i < NUM_RUNS; i++) {
                struct log* const log = &logs[i];
                int rc;
                gettimeofday(&log->pre_fork, NULL);
                // rc = syscall(SYS_clone, 0, NULL, NULL, NULL, NULL);
                rc = syscall(SYS_fork);
                if (rc == 0) {
                        gettimeofday(&log->in_child, NULL);
                        exit(0);
                }
                log->pid = rc;
                gettimeofday(&log->in_parent, NULL);
                waitpid(rc, NULL, 0);
                gettimeofday(&log->after_exit, NULL);
        }
}

struct options {
        int num_mappings;
};

static struct options parse_options(int argc, char **argv) {
        void usage() {
                printf("Usage: %s num_mappings\n", argc >= 1 ? argv[0] : "clone_bench");
                exit(1);
        }
        if (argc < 2) usage();
        return (struct options) { .num_mappings = atoi(argv[1]) };
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
        run(logs);
        run(logs);
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
