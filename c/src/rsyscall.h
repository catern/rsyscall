#include <stdint.h>

struct syscall {
        int sys;
        uint64_t args[6];
};

struct syscall_response {
        int64_t ret;
        uint32_t err;
};
