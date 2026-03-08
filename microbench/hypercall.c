/*
 * hypercall.c — Measure hypercall (VMCALL) roundtrip cost in CPU cycles.
 *
 * Reproduces the "Hypercall" row of Table 3 in the DVH ASPLOS'20 paper.
 * Must be compiled and run INSIDE the target VM (L1 for "VM" column,
 * L2 for "nested VM" column, L3 for "L3 VM" column).
 *
 * Build:  gcc -O2 -o hypercall hypercall.c
 * Run:    ./hypercall
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <sched.h>

#define ITERATIONS 10000
#define WARMUP     1000

/* Serialising RDTSC: lfence drains the out-of-order pipeline before reading. */
static inline uint64_t rdtsc_ordered(void)
{
	uint32_t lo, hi;
	asm volatile("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	return ((uint64_t)hi << 32) | lo;
}

/* Check whether we are running inside a KVM guest via CPUID leaf 0x40000000. */
static int kvm_guest(void)
{
	uint32_t eax, ebx, ecx, edx;
	asm volatile("cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(0x40000000) : );
	/* KVM signature: "KVMKVMKVM\0" in EBX, ECX, EDX */
	return (ebx == 0x4b4d564b && ecx == 0x564b4d56 && edx == 0x0000004d);
}

static volatile int got_sigill;
static void sigill_handler(int sig) { got_sigill = 1; }

int main(void)
{
	cpu_set_t cs;
	CPU_ZERO(&cs);
	CPU_SET(0, &cs);
	sched_setaffinity(0, sizeof(cs), &cs);

	if (!kvm_guest()) {
		fprintf(stderr,
			"WARNING: KVM signature not found. "
			"Running vmcall outside a VM will likely crash.\n");
	}

	/* Safety net: if vmcall raises SIGILL we bail cleanly. */
	signal(SIGILL, sigill_handler);

	/* Warmup — let branch predictors and caches settle. */
	for (int i = 0; i < WARMUP; i++) {
		asm volatile("vmcall" ::: "memory");
		if (got_sigill) {
			fprintf(stderr,
				"SIGILL: vmcall not supported "
				"(not inside a VMX guest?)\n");
			return 1;
		}
	}

	uint64_t start = rdtsc_ordered();
	for (int i = 0; i < ITERATIONS; i++)
		asm volatile("vmcall" ::: "memory");
	uint64_t end = rdtsc_ordered();

	printf("Hypercall: %lu cycles avg  (%d iterations)\n",
	       (end - start) / ITERATIONS, ITERATIONS);
	printf("Paper reference — VM: 1,575  nested VM: 37,733  L3 VM: 857,578\n");
	return 0;
}
