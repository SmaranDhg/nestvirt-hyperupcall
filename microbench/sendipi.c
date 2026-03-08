/*
 * sendipi.c — Measure IPI send-and-receive cost in CPU cycles.
 *
 * Reproduces the "SendIPI" row of Table 3 in the DVH ASPLOS'20 paper.
 * "Send IPI to CPU that is idle which needs to wakeup and switch to
 *  running destination VM vCPU to receive IPI."
 *
 * Methodology:
 *   The paper measures the time from when the source vCPU initiates an IPI
 *   (writing APIC ICR) to when the destination vCPU — which was idle/sleeping
 *   — receives it.  Writing the APIC ICR causes a VM-exit in a nested VM,
 *   triggering the guest→host→guest exit chain.
 *
 *   From user space we cannot write the APIC ICR directly (ring-0 only).
 *   We approximate the same effect by using the kernel's sched_setaffinity
 *   to force a cross-CPU wakeup, which internally sends a reschedule IPI:
 *
 *     CPU 0 (sender):  sets a futex and calls FUTEX_WAKE
 *     CPU 1 (receiver): sleeps on FUTEX_WAIT (truly descheduled — idle vCPU)
 *
 *   FUTEX_WAKE causes the kernel to send a reschedule IPI to CPU 1 to wake
 *   the blocked thread.  We measure: rdtsc before FUTEX_WAKE syscall returns
 *   to rdtsc after the receiver wakes and samples its TSC.
 *
 *   Accuracy note: the measured cycles include two syscall overheads
 *   (futex_wake + futex_wait return) in addition to the IPI chain.  At VM
 *   level the two syscalls each cost ~1000–2000 extra cycles; at nested-VM
 *   level the IPI chain dominates (~39k cycles) so the distortion is small.
 *
 * Requirements:
 *   - At least 2 vCPUs in the VM (check: nproc)
 *   - Run INSIDE the target VM
 *
 * Build:  gcc -O2 -pthread -o sendipi sendipi.c
 * Run:    ./sendipi
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <stdatomic.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <errno.h>

#define ITERATIONS  10000
#define WARMUP      500

static int futex_var = 0;   /* shared futex word */

static uint64_t sender_ts[ITERATIONS + WARMUP];   /* rdtsc before wake */
static uint64_t recv_ts  [ITERATIONS + WARMUP];   /* rdtsc after wakeup */

static atomic_int iter_idx  = 0;  /* current iteration (written by sender) */
static atomic_int recv_done = 0;  /* receiver signals it captured rdtsc */

static inline uint64_t rdtsc_ordered(void)
{
	uint32_t lo, hi;
	asm volatile("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
	return ((uint64_t)hi << 32) | lo;
}

static long futex_wait(int *uaddr, int val)
{
	return syscall(SYS_futex, uaddr, FUTEX_WAIT, val, NULL, NULL, 0);
}

static long futex_wake(int *uaddr, int n)
{
	return syscall(SYS_futex, uaddr, FUTEX_WAKE, n, NULL, NULL, 0);
}

/* Receiver thread — pinned to CPU 1, sleeps between each iteration. */
static void *receiver(void *arg)
{
	cpu_set_t cs;
	CPU_ZERO(&cs);
	CPU_SET(1, &cs);
	if (pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs) != 0) {
		fprintf(stderr, "receiver: cannot pin to CPU 1\n");
		return NULL;
	}

	int total = ITERATIONS + WARMUP;
	for (int i = 0; i < total; i++) {
		/* Go to sleep: block until sender sets futex_var = 1 */
		__atomic_store_n(&futex_var, 0, __ATOMIC_SEQ_CST);
		futex_wait(&futex_var, 0);      /* woken by sender */

		/* Capture TSC as early as possible after wakeup */
		recv_ts[i] = rdtsc_ordered();
		atomic_store(&recv_done, 1);
	}
	return NULL;
}

int main(void)
{
	if (sysconf(_SC_NPROCESSORS_ONLN) < 2) {
		fprintf(stderr,
			"Need at least 2 vCPUs.  "
			"Current VM has only 1.\n");
		return 1;
	}

	/* Pin sender to CPU 0 */
	cpu_set_t cs;
	CPU_ZERO(&cs);
	CPU_SET(0, &cs);
	sched_setaffinity(0, sizeof(cs), &cs);

	pthread_t thr;
	if (pthread_create(&thr, NULL, receiver, NULL) != 0) {
		perror("pthread_create");
		return 1;
	}

	for (int i = 0; i < ITERATIONS + WARMUP; i++) {
		/*
		 * Wait for the receiver to reset the futex and go back to
		 * sleep before we fire the next wake.
		 */
		while (__atomic_load_n(&futex_var, __ATOMIC_SEQ_CST) != 0)
			asm volatile("pause" ::: "memory");

		/* Small delay to let the receiver enter futex_wait */
		usleep(100);

		/* Reset recv_done before waking */
		atomic_store(&recv_done, 0);

		/* Record send timestamp, then wake receiver */
		sender_ts[i] = rdtsc_ordered();
		__atomic_store_n(&futex_var, 1, __ATOMIC_SEQ_CST);
		futex_wake(&futex_var, 1);

		/* Wait until receiver has recorded its wakeup timestamp */
		while (!atomic_load(&recv_done))
			asm volatile("pause" ::: "memory");
	}

	pthread_join(thr, NULL);

	/* Compute average over post-warmup iterations */
	uint64_t total = 0;
	for (int i = WARMUP; i < ITERATIONS + WARMUP; i++)
		total += recv_ts[i] - sender_ts[i];

	printf("SendIPI (cross-CPU wakeup via futex): %lu cycles avg  "
	       "(%d iterations)\n",
	       total / ITERATIONS, ITERATIONS);
	printf("Paper reference — VM: 3,273  nested VM: 39,456  L3 VM: 787,971\n");
	printf("Note: includes futex syscall overhead on both sides.\n"
	       "      At nested-VM levels the VM-exit chain dominates.\n");
	return 0;
}
