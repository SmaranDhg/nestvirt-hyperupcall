
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


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
        (void) getpid();
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf("sendipi [baseline] avg latency: %llu %s\n", (unsigned long long)(total_cycles / ITERS), "cycles");
    return 0;
}

