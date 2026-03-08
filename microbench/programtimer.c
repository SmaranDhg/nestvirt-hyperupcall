/*
 * programtimer.c — Measure LAPIC TSC-deadline timer programming cost.
 *
 * Reproduces the "ProgramTimer" row of Table 3 in the DVH ASPLOS'20 paper.
 * "Program LAPIC timer in TSC-Deadline mode."
 *
 * In a VM, writing MSR IA32_TSC_DEADLINE (0x6E0) causes a VM-exit so the
 * hypervisor can virtualise the LAPIC timer.  We measure the roundtrip cost
 * of that write using RDTSC.
 *
 * MSR access requires ring-0.  From user space the only practical interface
 * is the kernel's MSR driver (/dev/cpu/N/msr).  The pwrite() syscall adds a
 * small constant overhead (~few hundred cycles for the syscall itself), but
 * the dominant cost at nested-VM levels is the VM-exit chain (tens of
 * thousands of cycles), so the distortion is minor.
 *
 * Requirements:
 *   - modprobe msr            (load the MSR driver)
 *   - Run as root
 *   - CPU must support TSC-deadline: CPUID.01H:ECX[24]=1
 *   - Run INSIDE the target VM
 *
 * Build:  gcc -O2 -o programtimer programtimer.c
 * Run:    modprobe msr && sudo ./programtimer
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

#define MSR_IA32_TSC_DEADLINE  0x6E0UL

#define ITERATIONS  10000
#define WARMUP      1000

/* Arm the timer ~1 second in the future so it never actually fires. */
#define TSC_FUTURE_OFFSET  3000000000ULL   /* ~1 s at 3 GHz */

static inline uint64_t rdtsc_ordered(void)
{
	uint32_t lo, hi;
	asm volatile("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	return ((uint64_t)hi << 32) | lo;
}

static int check_tsc_deadline(void)
{
	uint32_t ecx = 0;
	asm volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");
	return (ecx >> 24) & 1;
}

/*
 * Write 'val' to the given MSR using the /dev/cpu/0/msr interface.
 * Returns 0 on success, -1 on failure.
 */
static int msr_write(int fd, uint32_t msr, uint64_t val)
{
	return (pwrite(fd, &val, sizeof(val), msr) == sizeof(val)) ? 0 : -1;
}

static uint64_t msr_read(int fd, uint32_t msr)
{
	uint64_t val = 0;
	(void)pread(fd, &val, sizeof(val), msr);
	return val;
}

int main(void)
{
	cpu_set_t cs;
	CPU_ZERO(&cs);
	CPU_SET(0, &cs);
	sched_setaffinity(0, sizeof(cs), &cs);

	if (!check_tsc_deadline()) {
		fprintf(stderr, "TSC-deadline mode not supported by CPU "
			"(CPUID.01H:ECX[24]=0)\n");
		return 1;
	}

	int fd = open("/dev/cpu/0/msr", O_RDWR);
	if (fd < 0) {
		fprintf(stderr,
			"Cannot open /dev/cpu/0/msr\n"
			"  Try:  modprobe msr  and run as root\n");
		perror("open");
		return 1;
	}

	printf("Current IA32_TSC_DEADLINE = 0x%lx\n",
	       msr_read(fd, MSR_IA32_TSC_DEADLINE));

	/* Warmup: arm then immediately disarm (write 0) */
	for (int i = 0; i < WARMUP; i++) {
		uint64_t future = rdtsc_ordered() + TSC_FUTURE_OFFSET;
		msr_write(fd, MSR_IA32_TSC_DEADLINE, future);
		msr_write(fd, MSR_IA32_TSC_DEADLINE, 0);  /* disarm */
	}

	/*
	 * Measure only the arm write; disarming is outside the timed region.
	 * This matches the paper's description: one WRMSR to the deadline MSR.
	 */
	uint64_t total = 0;
	for (int i = 0; i < ITERATIONS; i++) {
		uint64_t future = rdtsc_ordered() + TSC_FUTURE_OFFSET;

		uint64_t t0 = rdtsc_ordered();
		msr_write(fd, MSR_IA32_TSC_DEADLINE, future);
		uint64_t t1 = rdtsc_ordered();

		msr_write(fd, MSR_IA32_TSC_DEADLINE, 0);  /* disarm outside timed region */
		total += t1 - t0;
	}

	printf("ProgramTimer: %lu cycles avg  (%d iterations)\n",
	       total / ITERATIONS, ITERATIONS);
	printf("Paper reference — VM: 2,005  nested VM: 43,359  L3 VM: 1,033,946\n");
	printf("Note: includes one pwrite() syscall; dominant cost is the VM-exit.\n");

	close(fd);
	return 0;
}
