/*
 * ProgramTimer benchmark kernel module — measures the cost of writing to
 * the APIC timer initial-count register (APIC_TMICT). This is the privileged
 * operation that programs a hardware timer.
 *
 * We save/restore the original APIC timer state so the kernel's clockevents
 * framework is not disrupted.
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD
 * Run:   sudo insmod timer_bench.ko [iters=N]; dmesg | tail
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <asm/apic.h>
#include <asm/msr.h>

static int iters = 1000;
module_param(iters, int, 0644);
MODULE_PARM_DESC(iters, "Number of iterations (default 1000)");

static int __init timer_bench_init(void)
{
	unsigned long long start, end, total = 0;
	unsigned long flags;
	u32 saved_lvtt, saved_tdcr, saved_tmict;
	int i;

	if (iters <= 0)
		iters = 1000;

	pr_info("timer_bench: program APIC timer, %d iterations\n", iters);

	local_irq_save(flags);

	saved_lvtt  = apic_read(APIC_LVTT);
	saved_tdcr  = apic_read(APIC_TDCR);
	saved_tmict = apic_read(APIC_TMICT);

	apic_write(APIC_TMICT, 0);

	for (i = 0; i < iters; i++) {
		barrier();
		start = rdtsc_ordered();
		apic_write(APIC_TMICT, 1000000);
		end = rdtsc_ordered();
		total += (end - start);

		apic_write(APIC_TMICT, 0);
	}

	apic_write(APIC_LVTT,  saved_lvtt);
	apic_write(APIC_TDCR,  saved_tdcr);
	apic_write(APIC_TMICT, saved_tmict);

	local_irq_restore(flags);

	pr_info("timer_bench: avg latency %llu cycles\n", total / iters);

	return 0;
}

static void __exit timer_bench_exit(void)
{
	pr_info("timer_bench: module removed\n");
}

module_init(timer_bench_init);
module_exit(timer_bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Program-timer latency benchmark (APIC TMICT write, cycles)");
