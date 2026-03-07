
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

#define SAMPLE_FREQ 1000
#define DURATION_S  5

int main(void) {
    struct timespec t0, t1;
    long long n = (long long)SAMPLE_FREQ * DURATION_S;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    printf("ProgramTimer [baseline]: %lld getpid() calls (equiv %d Hz * %ds)...\n",
           (long long)n, SAMPLE_FREQ, DURATION_S);
    for (long long i = 0; i < n; i++)
        (void) getpid();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000LL
                         + (t1.tv_nsec - t0.tv_nsec) / 1000000LL;
    printf("ProgramTimer [baseline]: ran %lld ms, %lld getpid() calls\n",
           elapsed_ms, n);
    return 0;
}

