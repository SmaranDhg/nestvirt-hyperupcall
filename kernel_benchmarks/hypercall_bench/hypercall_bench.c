/*
 * Hypercall benchmark kernel module — measures vmcall round-trip latency
 * from kernel space (ring 0). The vmcall instruction is the privileged
 * operation an OS uses to call into the hypervisor.
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod hypercall_bench.ko [iters=N] [nr=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/msr.h>

static inline long do_vmcall(long nr, long a1, long a2, long a3)
{
	long ret;

	asm volatile("vmcall"
		: "=a" (ret)
		: "a" (nr), "b" (a1), "c" (a2), "d" (a3)
		: "memory");
	return ret;
}

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static int nr = 11;
module_param(nr, int, 0644);
MODULE_PARM_DESC(nr, "Hypercall number (default 11 = KVM_HC_SCHED_YIELD)");

static int __init hypercall_bench_init(void)
{
	unsigned long long start, end, total = 0;
	int i;

	if (iters <= 0)
		iters = 1000;

	pr_info("hypercall_bench: vmcall round-trip, nr=%d, %d iterations\n",
		nr, iters);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();
		do_vmcall(nr, 0, 0, 0);
		end = rdtsc_ordered();
		total += (end - start);
	}

	pr_info("hypercall_bench: avg latency %llu cycles\n", total / iters);

	return 0;
}

static void __exit hypercall_bench_exit(void)
{
	pr_info("hypercall_bench: module removed\n");
}

module_init(hypercall_bench_init);
module_exit(hypercall_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Hypercall (vmcall) round-trip latency benchmark (cycles)");
