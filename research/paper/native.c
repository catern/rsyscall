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
#include <signal.h>
#include <err.h>
#include <sched.h>
#include <spawn.h>

enum proc_create {
        FORK,
        VFORK,
        POSIX_SPAWN,
};

void run(enum proc_create mode, char **envp, int count) {
        for (int i = 0; i < count; i++) {
                int pid;
                switch (mode) {
                case FORK: {
                        char *argv[] = {"true", NULL};
                        pid = fork();
                        if (pid == 0) {
                                execve(TRUE_PATH, argv, envp);
                                err(1, "execve");
                        }
                } break;
                case VFORK: {
                        char *argv[] = {"true", NULL};
                        pid = vfork();
                        if (pid == 0) {
                                execve(TRUE_PATH, argv, envp);
                                err(1, "execve");
                        }
                } break;
                case POSIX_SPAWN: {
                        char *argv[] = {"true", NULL};
                        int rc = posix_spawn(&pid, TRUE_PATH, NULL, NULL, argv, envp);
                        if (rc < 0) {
                                err(1, "posix_spawn");
                        }
                } break;
                }
                waitpid(pid, NULL, 0);
        }
}

struct options {
        enum proc_create mode;
        int num_mappings;
};

static struct options parse_options(int argc, char **argv) {
        void usage() {
                printf("Usage: %s mode num_mappings\n", argc >= 1 ? argv[0] : "native_bench");
                exit(1);
        }
        if (argc < 3) usage();
        enum proc_create mode;
        if (!strcmp(argv[1], "fork")) {
                mode = FORK;
        } else if (!strcmp(argv[1], "vfork")) {
                mode = VFORK;
        } else if (!strcmp(argv[1], "posix_spawn")) {
                mode = POSIX_SPAWN;
        } else {
                errx(1, "invalid mode %s", argv[1]);
        }
        return (struct options) {
                .mode = mode,
                .num_mappings = atoi(argv[2]),
        };
}

int main(int argc, char **argv, char **envp) {
        struct options opt = parse_options(argc, argv);
        /* set up memory mappings with a lot of memory */
        for (int i = 0; i < opt.num_mappings; i++) {
                char* addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
                // touch the memory
                *addr = 1;
        }
        /* run the benchmark */
        struct timeval before, after;
        /* prep */
        run(opt.mode, envp, 10);
        gettimeofday(&before, NULL);
        const int num_runs = 100;
        run(opt.mode, envp, num_runs);
        gettimeofday(&after, NULL);
        double total = (after.tv_sec - before.tv_sec) + (after.tv_usec * 0.000001f)
                - (before.tv_usec * 0.000001f);
        printf("%lf\n", total/num_runs);
}
