/*
 * ProgramTimer benchmark kernel module — measures the cost of programming
 * the Local APIC timer (3 APIC register writes).
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod timer_bench.ko [iters=N] [initial_count=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/apic.h>
#include <asm/msr.h>

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static int initial_count = 1000000;
module_param(initial_count, int, 0644);
MODULE_PARM_DESC(initial_count, "APIC timer initial count (default 1000000)");

static int __init timer_bench_init(void)
{
	unsigned long long start, end, total = 0;
	int i;

	if (iters <= 0)
		iters = 1000;

	pr_info("timer_bench: program APIC timer, %d iterations\n", iters);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();

		apic_write(APIC_LVTT, APIC_LVT_TIMER_PERIODIC | 32);
		apic_write(APIC_TDCR, APIC_TDR_DIV_16);
		apic_write(APIC_TMICT, initial_count);

		end = rdtsc_ordered();
		total += (end - start);
	}

	/* Stop the timer so we don't leave it firing. */
	apic_write(APIC_TMICT, 0);

	pr_info("timer_bench: avg latency %llu cycles\n", total / iters);

	return 0;
}

static void __exit timer_bench_exit(void)
{
	apic_write(APIC_TMICT, 0);
	pr_info("timer_bench: module removed\n");
}

module_init(timer_bench_init);
module_exit(timer_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Program-timer latency benchmark (APIC timer, cycles)");
