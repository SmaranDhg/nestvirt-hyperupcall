
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>


#if defined(__i386__) || defined(__x86_64__)
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}
#define USE_CYCLES 1
#else
#include <time.h>
static inline unsigned long long rdtsc(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}
#define USE_CYCLES 0
#endif


#define ITERS 50

int main(void) {
    unsigned long long total_cycles = 0;
    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) close(fd);
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf("devnotify [baseline] avg latency: %llu %s\n", (unsigned long long)(total_cycles / ITERS), USE_CYCLES ? "cycles" : "ns");
    return 0;
}

