
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}


#define ITERS 50

int main(void) {
    unsigned long long total_cycles = 0;
    for (int i = 0; i < ITERS; i++) {
        unsigned long long t0 = rdtsc();
        (void) getpid();
        unsigned long long t1 = rdtsc();
        total_cycles += (t1 - t0);
    }
    printf("hypercall [baseline] avg latency: %llu cycles\n", (unsigned long long)(total_cycles / ITERS));
    return 0;
}

