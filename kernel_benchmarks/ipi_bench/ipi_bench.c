/*
 * IPI benchmark kernel module — measures request-IPI latency (send + handle)
 * using smp_call_function_single(). Same privileged operation as the userspace
 * sendipi benchmark (baseline/hyperupcall), but in-kernel on bare metal.
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod ipi_bench.ko [target_cpu=N] [iters=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <asm/msr.h>

static void ipi_handler(void *info)
{
	/* Empty handler */
}

static int target_cpu = 1;
module_param(target_cpu, int, 0644);
MODULE_PARM_DESC(target_cpu, "Target CPU for IPI (default 1)");

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static int __init ipi_bench_init(void)
{
	unsigned long long start, end, total = 0;
	int cpu = target_cpu;
	int i;

	if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_online(cpu)) {
		pr_info("ipi_bench: CPU %d not available (nr_cpu_ids=%d)\n",
			cpu, nr_cpu_ids);
		return -EINVAL;
	}

	if (iters <= 0)
		iters = 1000;

	pr_info("ipi_bench: request-IPI latency, CPU %d -> CPU %d, %d iterations\n",
		smp_processor_id(), cpu, iters);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();
		smp_call_function_single(cpu, ipi_handler, NULL, 1);
		end = rdtsc_ordered();
		total += (end - start);
	}

	pr_info("ipi_bench: avg latency %llu cycles (send+handle)\n", total / iters);

	return 0;
}

static void __exit ipi_bench_exit(void)
{
	pr_info("ipi_bench: module removed\n");
}

module_init(ipi_bench_init);
module_exit(ipi_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Request-IPI latency benchmark (smp_call_function_single, cycles)");
