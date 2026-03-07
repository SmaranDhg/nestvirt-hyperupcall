/*
 * DevNotify benchmark kernel module — measures device-notification latency.
 * Sends an IPI to a target CPU via smp_call_function_single (synchronous),
 * which is the kernel primitive for "notify a remote CPU and wait for ack."
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod devnotify_bench.ko [iters=N] [target_cpu=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <asm/msr.h>

static void notify_handler(void *info)
{
	/* Empty — just the IPI delivery + handler invocation is the cost. */
}

static int target_cpu = 1;
module_param(target_cpu, int, 0644);
MODULE_PARM_DESC(target_cpu, "Target CPU for notification (default 1)");

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static int __init devnotify_bench_init(void)
{
	unsigned long long start, end, total = 0;
	int cpu = target_cpu;
	int i;

	if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_online(cpu)) {
		pr_info("devnotify_bench: CPU %d not available\n", cpu);
		return -EINVAL;
	}

	if (cpu == smp_processor_id()) {
		for (cpu = 0; cpu < nr_cpu_ids; cpu++)
			if (cpu_online(cpu) && cpu != smp_processor_id())
				break;
		if (cpu >= nr_cpu_ids) {
			pr_info("devnotify_bench: need at least 2 online CPUs\n");
			return -EINVAL;
		}
	}

	if (iters <= 0)
		iters = 1000;

	pr_info("devnotify_bench: device-notification, CPU %d -> CPU %d, %d iterations\n",
		smp_processor_id(), cpu, iters);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();
		smp_call_function_single(cpu, notify_handler, NULL, 1);
		end = rdtsc_ordered();
		total += (end - start);
	}

	pr_info("devnotify_bench: avg latency %llu cycles\n", total / iters);

	return 0;
}

static void __exit devnotify_bench_exit(void)
{
	pr_info("devnotify_bench: module removed\n");
}

module_init(devnotify_bench_init);
module_exit(devnotify_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Device-notification latency benchmark (cross-CPU IPI, cycles)");
