#include <stdio.h>
#include <sys/resource.h>

int main() {
    struct rlimit lim;
    if (getrlimit(RLIMIT_STACK, &lim)) {
        fprintf(stderr, "get limit of stack size failed!");
        return 1;
    }
    printf("stack size: %ld\n", lim.rlim_cur);
    if (getrlimit(RLIMIT_NPROC, &lim)) {
        fprintf(stderr, "get limit of process failed!");
        return 1;
    }
    printf("process limit: %ld\n", lim.rlim_cur);
    if (getrlimit(RLIMIT_NOFILE, &lim)) {
       fprintf(stderr, "get max of file descriptor failed!");
       return 1; 
    }
    printf("max file descriptors: %ld\n", lim.rlim_max);
    return 0;
}
