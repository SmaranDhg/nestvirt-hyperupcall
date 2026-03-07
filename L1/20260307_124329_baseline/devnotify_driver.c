
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>


static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}


#define ITERS 1000

int main(void) {
    unsigned long long total_cycles = 0;
    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) close(fd);
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf("devnotify [baseline] avg latency: %llu %s\n", (unsigned long long)(total_cycles / ITERS), "cycles");
    return 0;
}

