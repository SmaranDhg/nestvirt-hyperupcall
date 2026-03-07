
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ITERS 100

int main(void) {
    struct timespec t0, t1;
    long long total_ns = 0;
    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) close(fd);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total_ns += (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);
    }
    printf("devnotify [baseline] avg latency: %lld ns\n", total_ns / ITERS);
    return 0;
}

