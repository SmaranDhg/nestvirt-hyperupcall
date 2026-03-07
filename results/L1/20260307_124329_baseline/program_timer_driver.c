
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}


#define SAMPLE_FREQ 1000
#define DURATION_S  5

int main(void) {
    unsigned long long t_start = rdtsc();
    long long n = (long long)SAMPLE_FREQ * DURATION_S;
    printf("ProgramTimer [baseline]: %lld getpid() calls (equiv %d Hz * %ds)...\n",
           (long long)n, SAMPLE_FREQ, DURATION_S);
    unsigned long long sum_cycles = 0;
    for (long long i = 0; i < n; i++) {
        unsigned long long t0 = rdtsc();
        (void) getpid();
        unsigned long long t1 = rdtsc();
        sum_cycles += (t1 - t0);
    }
    unsigned long long t_end = rdtsc();
    unsigned long long total_cycles = t_end - t_start;
    printf("ProgramTimer [baseline]: total %llu %s, avg %llu %s/call\n",
           (unsigned long long)total_cycles, "cycles",
           (unsigned long long)(sum_cycles / n), "cycles");
    return 0;
}

